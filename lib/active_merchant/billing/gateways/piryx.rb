require 'rexml/document'
require 'digest/md5'

module ActiveMerchant #:nodoc:
  module Billing #:nodoc:
    class PiryxGateway < Gateway

      self.money_format = :dollars
      self.supported_cardtypes = [:visa, :master, :american_express, :discover]
      self.supported_countries = ['US']
      self.display_name = 'Piryx'
      self.homepage_url = 'http://www.piryx.com'
      self.default_currency = 'USD'

      def initialize(options = {})
        requires!(options, :account, :api_key, :api_secret, :campaign)
        @options = options
        super
      end  
      
      def authorize(money, credit_card_or_reference, options = {})
        # Throw unsupported exception
      end
            
      def purchase(money, credit_card_or_reference, options = {})
        post = {}
        
        add_amount(post, money, options)
        add_payment(post, credit_card_or_reference, options)
        add_address(post, options)

        commit(:purchase, post)
      end
      
      def capture(money, authorization, options = {})
        # Throw unsupported exception
      end
      
      def void(identification, options = {})
        # Throw unsupported exception
      end
      
      def credit(money, identification, options = {})
        # Throw unsupported exception
      end
      
      def store(creditcard, options = {})                       
        # Throw unsupported exception
      end
      
      private                       

      def base_url()
        if test?
          "http://demo.tools.piryx.com/api/accounts/#{@options[:account]}/payments" 
        else
          "https://secure.piryx.com/api/accounts/#{@options[:account]}/payments" 
        end
      end
  
      def basic_auth(headers)
        auth_string = 'Basic ' + ["#{@options[:api_key]}:api"].pack('m').delete("\r\n")
        headers['authorization'] = [auth_string]
      end

      def add_amount(post, money, options = {})
        post['Amount']   = amount(money)
      end
      
      def add_amount_without_currency(post, money, options = {})
        post['Amount'] = amount(money)
      end

      def add_payment(post, payment, options)
        case
          when payment.class == ActiveMerchant::Billing::CreditCard
            then add_creditcard(post, payment, options)
          when payment.class == ActiveMerchant::Billing::Check
            then add_check(post, payment, options)
          else raise ArgumentError, "Unsupported payment type"
        end
      end
          
      def creditcard_type(credit_card)
        raw_type = credit_card.type
        if raw_type == 'visa'
          'Visa'
        elsif raw_type == 'master'
          'Mastercard'
        elsif raw_type == 'discover'
          'Discover'
        elsif raw_type == 'american_express'
          'Amex'
        end          
      end

      def add_creditcard(post, credit_card, options)
        post['Payment'] = creditcard_type(credit_card)
        post['FirstName'] = credit_card.first_name
        post['LastName'] = credit_card.last_name
        post['CardNumber']          = credit_card.number   
        post['CardSecurityCode']    = credit_card.verification_value
        post['CardExpirationMonth'] = format(credit_card.month, :two_digits)
        post['CardExpirationYear']   = format(credit_card.year, :four_digits)
      end

      def add_check(post, check, options)
        post['Payment'] = 'ECheck'
        post['FirstName'] = check.first_name
        post['LastName'] = check.last_name
        post['AccountNumber'] = check.account_number
        post['RoutingNumber'] = check.routing_number
      end
      
      def add_address(post, options)
        if address = options[:billing_address] || options[:address]
          post['BillingAddress1'] = address[:address1].to_s
          post['BillingAddress2'] = address[:address2].to_s unless address[:address2].blank?
          post['BillingCity']    = address[:city].to_s
          post['BillingState']   = address[:state].blank?  ? 'n/a' : address[:state]
          post['BillingZip']     = address[:zip].to_s
          post['Phone']   = address[:phone].to_s
        end
        
        if address = options[:shipping_address]
          post['Address1'] = address[:address1].to_s
          post['Address2'] = address[:address2].to_s unless address[:address2].blank?
          post['City']    = address[:city].to_s
          post['State']   = address[:state].blank?  ? 'n/a' : address[:state]
          post['Zip']     = address[:zip].to_s
        end
      end
      
      
      def add_description(post, options)
        post['Description'] = options[:description] unless options[:description].blank?
      end
      
      def commit(action, params)
        headers = {}
        
        response = parse(ssl_post(base_url, post_data(action, params), headers))
        
        Response.new(successful?(response), message_from(response), response, 
          :test => test?, 
          :authorization => response[:transaction]
        )
      end
      
      def successful?(response)
        response[:success]
      end

      def parse(data)
        response = {}
        
        doc = REXML::Document.new(data)
        
        success = false
        if doc.root.fully_expanded_name == 'Payment'
          doc.root.elements.each("Status") do |e| 
            if e.get_text.value == 'Accepted'
              success = true
            end 
          end
        end
        response[:success] = success

        if doc.root.fully_expanded_name == 'Error'
          message = nil
          doc.root.elements.each("Message") do |e| 
            message = e.get_text.value
          end
          code = nil
          doc.root.elements.each("Code") do |e| 
            code = e.get_text.value
          end
          response[:error_message] = message
          response[:error_code] = code
        end
     
        response
      end

      def message_from(response)
        if response[:success]
          nil
        else
          response[:error_message]
        end
      end
      
      def rfc3986_escape(value)
        return '' if value.nil?
        URI.escape(value, /[^.~0-9A-za-z\-]/)
      end

      def post_data(action, params = {})
        params['Signature'] = generate_signature('POST', params)        
        params.collect { |key, value| "#{key}=#{rfc3986_escape(value.to_s)}" }.join("&")
      end
  
      def generate_signature(http_method, params = nil)
         string_to_sign = "#{http_method}&#{rfc3986_escape(base_url)}&"

         is_first = true
         params_string = ''
         params.keys.sort.each do |key|
           if is_first
             is_first = false
           else
             params_string += '&'
           end
           params_string += "#{key.to_s}=#{rfc3986_escape(params[key])}"
         end
         string_to_sign += rfc3986_escape(params_string)

         sha1 = HMAC::SHA1.new( @options[:api_secret] )
         sha1 << string_to_sign
         Base64.encode64( sha1.digest )
       end            

    end
  end
end

