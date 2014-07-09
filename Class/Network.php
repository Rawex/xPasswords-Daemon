<?php

namespace xPasswords;

class Request {
    
	public static $lastError = false;

    public static function make($hostname, $datas) {
        
        try {

            $request = \Requests::post('http://' . $hostname, [
                'User-Agent' => XPASSWORDS_IO_USERAGENT, // Custom UA
            ],
            Core::compress( // Compress with Gzip
                Core::$CipherNetwork->encrypt( // Encrypt with AES 256 bits
                    Core::encode( // Encode with JSON
                        $datas // Original array
                    )
                )
            ), [
                'timeout' => XPASSWORDS_IO_TIMEOUT_OUT, // Timeout
                'proxy' => [
                    'type' => 'SOCKS5',
                    'authentication' => [
                        '127.0.0.1:9050'
                    ],
                ], // SOCKS Proxy
                'follow_redirects' => false, // Don't follow redirections
                'useragent' => XPASSWORDS_IO_USERAGENT, // Custom UA
            ]);
            
        } catch (\Exception $e) {
            static::$lastError = $e->xdebug_message;
            return false;
        }
        
        $hostname = NULL;
        $datas = NULL;
        
        return $request;
    }
};

class Network {
    
    public static $HTTPResponseHeaders = false;
    
    public static function openSocket($Controller) {
        
        // Add \xPasswords\
        $Controller = '\xPasswords\\' . $Controller;
        
        $socket = new \React\Socket\Server($Controller::$reactLoop);
        $http = new \React\Http\Server($socket);
        
        // Set Headers
        static::$HTTPResponseHeaders = [
            'Content-Type' => 'text/plain',
            'X-Powered-By' => XPASSWORDS_IO_USERAGENT
        ];
        
        // When an connection is kicked, this function is used
        $errSend = function($response, $request) {
            
            // Set container to NULL
            $request->Container = NULL;
            
            // Prepare response
            $headers = static::$HTTPResponseHeaders;
            $output = Core::compress(Core::$CipherNetwork->encrypt(Core::encode(['received' => false])));
            $headers['Content-Length'] = strlen($output);
            
            // Send it
            $response->writeHead(403, $headers);
            $response->end($output);
            
            return true;
        };

        $http->on('request', function($request, $response) use ($errSend, $Controller) {
            
            // New connection detected
            echo Core::say('[NETWORK] New connection detected.', ['color' => 'green']);
            
            // Detect User-Agent            
            if(empty($request->getHeaders()['User-Agent'])) {
                echo Core::say('[NETWORK] [ERROR] Empty User-Agent detected.', ['color' => 'red']);
                $errSend($response, $request);
                return false;
            }
            if(XPASSWORDS_IO_USERAGENT != $request->getHeaders()['User-Agent']) {
                echo Core::say('[NETWORK] [ERROR] Invalid User-Agent detected.', ['color' => 'red']);
                echo Core::say('[NETWORK] [ERROR] Details: ' . $request->getHeaders()['User-Agent'], ['color' => 'red']);
                $errSend($response, $request);
                return false;
            }
                        
            // Detect Content-Length
            if(!isset($request->getHeaders()['Content-Length']) OR empty($request->getHeaders()['Content-Length'])) {
                echo Core::say('[NETWORK] [ERROR] Empty Content-Length detected.', ['color' => 'red']);
                $errSend($response, $request);
                return false;
            }
            if(!ctype_digit($request->getHeaders()['Content-Length'])) {
                echo Core::say('[NETWORK] [ERROR] Invalid Content-Length detected.', ['color' => 'red']);
                $errSend($response, $request);
                return false;
            }
                        
            // Declare buffer container
            $request->Container = '';
            
            // Prevent possible DoS
            $timer = $Controller::$reactLoop->addTimer(XPASSWORDS_IO_TIMEOUT_IN, function() use ($response, $request, $errSend) {
                echo Core::say('[NETWORK] [ERROR] Timeout for request. Only ' . strlen($request->Container) . ' bytes of ' . $request->getHeaders()['Content-Length'] . ' datas received', ['color' => 'red']);
                $errSend($response, $request);
                return true;
            });
            
            // When receive datas
            $request->on('data', function($data) use ($request, $response, $timer, $Controller) {

                // Add datas to buffer
                $request->Container .= $data;
                                
                // Detect if this is the end
                if($request->getHeaders()['Content-Length'] != strlen($request->Container)) {
                   return false;
                }
                
                // Cancel timer
                $timer->cancel();
                                
                // DECLARE, PUSHBACK
                if($Controller::queue($request->Container, $response)) {
                    $request->Container = NULL;
                    return true;
                }
                
                $request->Container = NULL;
                $response->writeHead(403, static::$HTTPResponseHeaders);
                $response->end(Core::compress(Core::$CipherNetwork->encrypt(Core::encode(['received' => false]))));
                return false;
            });
        });
        
        $listenPort = ($Controller == '\xPasswords\Client' ? XPASSWORDS_CLIENT_LISTEN_PORT : XPASSWORDS_SERVER_LISTEN_PORT);
        
        // Try to listen on the given port...
        try {
            $socket->listen($listenPort, '127.0.0.1');
        } catch(\React\Socket\ConnectionException $e) {
            switch(strpos($e->getMessage(), 'Address already in use')) {
                
                // Another instance
                case true: echo Core::say('[NETWORK] [SERVER] Another instance is running, kill it before launching a new one.', ['color' => 'red']); break;
                
                case false: // Unknown error
                echo Core::say('[NETWORK] [SERVER] The server cannot be started due to an fatal error ! Exiting...', ['color' => 'red']);
                echo Core::say('[NETWORK] [SERVER] Details: ' . $e->getMessage(), ['color' => 'red']);
                break;
            }
            exit(0);
        }
        
        // Everything is fine !
        echo Core::say('[NETWORK] [SERVER] Server now listen on ' . XPASSWORDS_LISTEN_IP . ':' . (int) $listenPort, ['color' => 'green']);
        
        // Free memory
        $listenPort = NULL;
        
        // Run the loop
        $Controller::$reactLoop->run();
    }
};