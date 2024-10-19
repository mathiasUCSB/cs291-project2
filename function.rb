# frozen_string_literal: true

require 'json'
require 'jwt'
require 'pp'

def main(event:, context:)
  case event['path']
  when '/'
    if event['httpMethod'] == 'GET'
      return handle_get(event)
    else
      return response(body: {error: 'Method Not Allowed'}, status: 405)
    end
  when '/auth/token'
    if event['httpMethod'] == 'POST'
      return handle_post(event)
    else
      return response(body: {error: 'Method Not Allowed'}, status: 405)
    end
  end

  response(body: {error: 'Not Found'}, status: 404)
end

def handle_post(event)
  # Guard clause for valid content-type
  unless event['headers']['Content-Type'] == 'application/json'
      return response(body: {error: 'Unsupported Media Type'}, status: 415)
  end

  # Try to parse JSON body
  begin
    body = JSON.parse(event['body'])
  rescue
    return response(body: {error: 'Unprocessable Entity'}, status: 422)
  end

  # Generate token
  payload = {
    data: body,
    exp: Time.now.to_i + 5,
    nbf: Time.now.to_i + 2
  }
  token = JWT.encode(payload, ENV['JWT_SECRET'], 'HS256')

  return response(body: {token: token}, status: 201)
end

def handle_get(event)
  auth_header = event['headers']['Authorization']
  unless auth_header && auth_header.start_with?('Bearer ')
    return response(body: {error: 'Forbidden'}, status: 403)
  end

  begin
    token = JWT.decode(auth_header.split(' ')[1], ENV['JWT_SECRET'], true, {algorithm: 'HS256'})
    data = token[0]['data']
  rescue JWT::ExpiredSignature, JWT::ImmatureSignature
    return response(body: {error: 'Unauthorized'}, status: 401)
  rescue JWT::DecodeError
    return response(body: {error: 'Forbidden'}, status: 403)
  end
  
  response(body: data, status: 200)
end


def response(body: nil, status: 200)
  {
    body: body ? body.to_json + "\n" : '',
    statusCode: status
  }
end

if $PROGRAM_NAME == __FILE__
  # If you run this file directly via `ruby function.rb` the following code
  # will execute. You can use the code below to help you test your functions
  # without needing to deploy first.
  ENV['JWT_SECRET'] = 'NOTASECRET'

  # Call /token
  PP.pp main(context: {}, event: {
               'body' => '{"name": "bboe"}',
               'headers' => { 'Content-Type' => 'application/json' },
               'httpMethod' => 'POST',
               'path' => '/token'
             })

  # # Generate a token
  payload = {
    data: { user_id: 128 },
    exp: Time.now.to_i + 1,
    nbf: Time.now.to_i
  }
  token = JWT.encode payload, ENV['JWT_SECRET'], 'HS256'
  # # Call
  PP.pp main(context: {}, event: {  
               'headers' => { 'Authorization' => "Bearer #{token}",
                              'Content-Type' => 'application/json' },
               'httpMethod' => 'GET',
               'path' => '/'
             })
end
