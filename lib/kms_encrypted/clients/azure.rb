module KmsEncrypted
    module Clients
      class Azure < Base
        @@access_token = nil
        @@access_token_expires_on = nil
        KV_ALGORITHM = 'RSA-OAEP-256'
        KV_API_VERSION = '7.4'

        def encrypt(plaintext, context: nil)
          body = {
            alg: KV_ALGORITHM,
            value: Base64.urlsafe_encode64(plaintext)
          }

          body[:aad] = generate_context(context) if context

          response = HTTParty.post(
            "https://#{vault_name}.vault.azure.net/keys/#{key_name}/encrypt?api-version=#{KV_API_VERSION}",
            :body => body.to_json,
            :headers => headers
          )

          raise "Error encrypting data with Azure KeyVault: #{response.parsed_response["error"]} - #{response.parsed_response["error_description"]}" if response.code != 200
          raise "Error encrypting data with Azure KeyVault: Response succeeded but did not contain kid or value" unless response.parsed_response.key?("kid") && response.parsed_response.key?("value")

          # The response contains the key version and ciphertext in separate fields. In order to automatically decrypt
          # ciphertext generated with an old key version, we need to store the key version in the cipher text.
          Base64.urlsafe_encode64(response.parsed_response.to_json)
        end

        def decrypt(ciphertext, context: nil)
          ciphertext_parsed = JSON.parse(Base64.urlsafe_decode64(ciphertext))
          kid = ciphertext_parsed["kid"]
          value = ciphertext_parsed["value"]
          key_version = kid.split('/').last

          body = {
            alg: KV_ALGORITHM,
            value: value
          }

          body[:aad] = generate_context(context) if context

          response = HTTParty.post(
            "https://#{vault_name}.vault.azure.net/keys/#{key_name}/#{key_version}/decrypt?api-version=#{KV_API_VERSION}",
            :body => body.to_json,
            :headers => headers
          )

          raise "Error decrypting data with Azure KeyVault: #{response.parsed_response["error"]} - #{response.parsed_response["error_description"]}" if response.code != 200
          raise "Error decrypting data with Azure KeyVault: Response succeeded but did not contain value" unless response.parsed_response.key?("value")

          Base64.urlsafe_decode64(response.parsed_response["value"])
        end

        private

        def vault_name
            key_id.split("/").second
        end

        def key_name
            key_id.split("/").third
        end

        def headers
            {
                'Authorization' => "Bearer #{access_token}",
                'Content-Type' => 'application/json'
            }
        end

        def access_token
            return @@access_token if @@access_token && @@access_token_expires_on && @@access_token_expires_on - 300 > Time.now.to_i

            params = {
                :client_id     => ENV['AZURE_KV_APP_CLIENT_ID'],
                :client_secret => ENV['AZURE_KV_APP_CLIENT_SECRET'],
                :grant_type    => "client_credentials",
                :resource      => "https://vault.azure.net"
            }
            response = HTTParty.post("https://login.microsoftonline.com/#{ENV['AZURE_KV_APP_TENANT_ID']}/oauth2/token", :body => params)

            raise "Error fetching Azure KeyVault access token: #{response.parsed_response["error"]} - #{response.parsed_response["error_description"]}" if response.code != 200

            @@access_token = response.parsed_response["access_token"]
            @@access_token_expires_on = response.parsed_response["expires_on"]&.to_i

            raise "Error fetching Azure KeyVault access token: Response succeeded but did not contain access token" if @@access_token.blank?

            @@access_token
        end

      end
    end
  end
