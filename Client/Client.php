<?php
namespace xPasswords;

// Load dependencies
require('../Class/Core.php');
require('Payments.php');

class Client {

    public static $reactLoop                = false;
    public static $workerCalculate          = [];
    public static $workerExchange           = [];
    public static $workerRefresher          = [];
    public static $workerSend               = [];
    public static $workerPayments           = [];

    public static function run() {

        // Check if this session is not in debug mode
        if(Core::getVar('debug') == 'true' AND
           !XPASSWORDS_IS_PRODUCTION) {

            define('_DEBUG_MODE', true);
            echo Core::say('[INFO] Debug mode set.', ['color' => 'blue']);
        }

        // Connect to MySQL Database using PDO
        if(!Bootstrap::DatabaseConnect(XPASSWORDS_FILENAME_CLIENT, Bootstrap::$DatabaseCredentials)) {
            echo Core::say('[ERROR] Unable to connect to the database.', ['color' => 'red']);
            return false;
        }
        
        // Create sockets
        static::$reactLoop = \React\EventLoop\Factory::create();

        // 0. Statistics
        static::$reactLoop->addPeriodicTimer(20, function() {
            echo Core::say('[SERVER] Current memory usage: ' . number_format((memory_get_usage() / 1024), 3) . 'K', ['color' => 'blue']);
        });

        // 1. Filtre et calcule les analyses en attente
        static::$reactLoop->addPeriodicTimer(5, function() {
            static::_analysisCalculate();
        });

        // 2. Analyser les scans en cours et recalculer leurs pourcentage (+ mettre le status terminé si ils le sont)
        static::$reactLoop->addPeriodicTimer(20, function() {
            static::_Refresher();
        });

        // 3. Envoies les combinaisons en attente au Daemon
        static::$reactLoop->addPeriodicTimer(15, function() {
            static::_analysisSend();
        });

        // 4. Regarde si un paiement BTC a été envoyé à une adresse généré, si oui, passe le paiement en vérifié et ajoute les crédits
        // Check les paiements non fait avec blocage du cours BTC + expiration en 30 minutes
        // Check les paiements fait avec les vérifications des mineurs + expiration en 24h
        static::$reactLoop->addPeriodicTimer(10, function() {
            static::_updatePayments();
        });

        // 5. Met à jour le cours BTC toute les demi-heures (et lors du lancement)
        static::$reactLoop->addPeriodicTimer(1800, function() {
            static::_updateExchange();
        });
        static::$reactLoop->addTimer(5, function() {
            static::_updateExchange();
        });
        
        // 6. Met à jour les fournisseurs e-mail (logins utilisés, disponibilité) et met en cache dans la mémoire
        echo Core::say('[PROVIDERS] [SERVER] Getting providers list.', ['color' => 'green']);
        static::_updateProviders();
        static::$reactLoop->addPeriodicTimer(1800, function() {
            echo Core::say('[PROVIDERS] [SERVER] Updating providers list.', ['color' => 'green']);
            static::_updateProviders();
        });
        
        // Run the webserver
        Network::openSocket('Client');
    }
    
    private static function _updateProviders() {
        
        // Get latest providers
        $stmt = Bootstrap::$Database->prepare('SELECT `sIdentifier`, `sEmails`, `sClassName` FROM `xProviders` WHERE `sStatus`=1');
        $stmt->execute();
        $xQueries = $stmt->fetchAll(\PDO::FETCH_OBJ);

        // Cleanup variable
        Core::$authenticationProviders = false;
        
        // Add each providers in memory
        foreach($xQueries as $iterator => $object) {
            echo Core::say('[PROVIDERS] [INFO] ' . $object->sIdentifier . ' support added.', ['color' => 'blue', 'noFilter' => true]);
            
            // Adding supported mails to memory
            Core::$authenticationProviders[ ucfirst(strtolower($object->sClassName)) ] = ['supportedDomains' => Core::decode($object->sEmails)];
        }
    }

    private static function _updateExchange() {

        // Create new child to proceed
        $sId = (count(static::$workerExchange) + 1);
        static::$workerExchange[ $sId ] = new \xPasswords\Child\Create([

            // React Loop
            'loop' => static::$reactLoop,

            // Type of child
            'type' => 'updateExchange',

            // Timeout
            'timeout' => 600, // 10 minutes max

            // Header text
            'header' => 'Updating BTC exchange...',

            // User custom defines
            'options' => [
                'title' => 'Exchange',
                'sId' => $sId,
            ]
        ]);
        static::$workerExchange[ $sId ]->on('exit', function($thisProcess) use ($sId) {
            // Free memory
            unset(Client::$workerExchange[ $sId ]); Client::$workerExchange[ $sId ] = false;
        });
        static::$workerExchange[ $sId ]->run();
    }

    private static function _updatePayments() {
        // @ workerPayments
        
        // Create new child to proceed
        $sId = (count(static::$workerPayments) + 1);
        static::$workerPayments[ $sId ] = new \xPasswords\Child\Create([

            // React Loop
            'loop' => static::$reactLoop,

            // Type of child
            'type' => 'updatePayments',

            // Timeout
            'timeout' => 600, // 10 minutes max

            // Header text
            'header' => 'Checking if there is any payments to verify...',

            // User custom defines
            'options' => [
                'title' => 'Payments',
                'sId' => $sId,
            ]
        ]);
        static::$workerPayments[ $sId ]->on('exit', function($thisProcess) use ($sId) {
            // Free memory
            unset(Client::$workerPayments[ $sId ]); Client::$workerPayments[ $sId ] = false;
        });
        static::$workerPayments[ $sId ]->run();
    }

    private static function _Refresher() {

        // Get RUNNING scans
        $stmt = Bootstrap::$Database->prepare('SELECT `sId`, `sPercentageVerified` FROM `xScanId` WHERE `sStatus`=2');
        $stmt->execute();
        $xQueries = $stmt->fetchAll(\PDO::FETCH_OBJ);
        if(empty($xQueries)) {
            return false;
        }

        $sId = (count(static::$workerRefresher) + 1);

        // Create new child to proceed
        static::$workerRefresher[ $sId ] = new \xPasswords\Child\Create([

            // React Loop
            'loop' => static::$reactLoop,

            // Type of child
            'type' => 'analysisRefresher',

            // Inbound datas
            'payload' => $xQueries,

            // Timeout
            'timeout' => 600, // 2 hours max

            // Header text
            'header' => 'Looking for running analysis to check...',

            // User custom defines
            'options' => [
                'title' => 'Refresher',
                'sId' => $sId,
            ]
        ]);
        static::$workerRefresher[ $sId ]->on('exit', function($thisProcess) use ($sId) {
            // Free memory
            unset(Client::$workerRefresher[ $sId ]); Client::$workerRefresher[ $sId ] = false;
        });

        static::$workerRefresher[ $sId ]->run();
    }

    private static function _analysisCalculate() {

        // Get new scans to calculate cost
        $stmt = Bootstrap::$Database->prepare('SELECT `sId`, `sFor`, `sAdvancedOptions` FROM `xScanId` WHERE `sStatus`=0 AND `sPercentageVerified`=0');
        $stmt->execute();
        $xQueries = $stmt->fetchAll(\PDO::FETCH_ASSOC);
        if(empty($xQueries)) {
            return false;
        }
        
        // Okay so here is one or more results
        foreach($xQueries as $xQuery) {

            // Set percentageVerified to 1 to prevent spawning another script
            $stmt = Bootstrap::$Database->prepare('UPDATE `xScanId` SET `sPercentageVerified`=1 WHERE `sId`=:sId');
            $stmt->execute([
                'sId' => $xQuery['sId'],
            ]);

            // Create new child to proceed
            $sId = (count(static::$workerCalculate) + 1);

            // Create new child to proceed
            static::$workerCalculate[ $sId ] = new \xPasswords\Child\Create([

                // React Loop
                'loop' => static::$reactLoop,

                // Type of child
                'type' => 'analysisCalculate',

                // Inbound datas
                'payload' => [
                    'scan' => $xQuery,
                    'providers' => Core::$authenticationProviders,
                ],

                // Timeout
                'timeout' => (2 * 3600), // 2 hours max

                // Header text
                'header' => 'Calculating scan #' . $xQuery['sId'] . '...',

                // User custom defines
                'options' => [
                    'title' => 'Calculate',
                    'sId' => $sId,
                ]
            ]);
            static::$workerCalculate[ $sId ]->on('response', function($thisProcess, $output) {

                switch($output['type']) {

                    case 'setPercentage': // Update percentage
                    $stmt = Bootstrap::$Database->prepare('UPDATE `xScanId` SET `sPercentageVerified`=:sPercentageVerified WHERE `sId`=:sId');
                    $stmt->execute([
                        'sPercentageVerified' => $output['childOutput'],
                        'sId' => $thisProcess->vars['payload']['sId'],
                    ]);
                    break;

                    case 'results': // Final results (?)
                    if(!$output['childOutput']) {
                        // Reverting because there was a problem with the scan
                        $stmt = Bootstrap::$Database->prepare('UPDATE `xScanId` SET `sPercentageVerified`=0 WHERE `sId`=:sId');
                        $stmt->execute([
                            'sId' => $thisProcess->vars['payload']['sId'],
                        ]);
                    }
                    break;
                }
            });
            static::$workerCalculate[ $sId ]->on('timeout', function($thisProcess) {                
                // Unlock the entry in database
                $stmt = Bootstrap::$Database->prepare('UPDATE `xScanId` SET `sPercentageVerified`=0 WHERE `sId`=:sId');
                $stmt->execute([
                    'sId' => $thisProcess->vars['payload']['sId'],
                ]);
            });
            static::$workerCalculate[ $sId ]->on('exit', function($thisProcess) use ($sId) {
                // Free memory
                unset(Client::$workerCalculate[ $sId ]); Client::$workerCalculate[ $sId ] = false;
            });

            static::$workerCalculate[ $sId ]->run();
        }
    }
    
    private static function _analysisSend() {

        $nbrOfCombinaisons = Bootstrap::$Database->prepare('SELECT COUNT(*) FROM `xCombinaisons` WHERE `isBusy`=0 AND `isSuccess`=0 AND `wasVerified`=0');
        $nbrOfCombinaisons->execute();
        $nbrOfCombinaisons = $nbrOfCombinaisons->fetch(\PDO::FETCH_ASSOC)['COUNT(*)'];

        // Check if here is one or more combinaisons to send
        if($nbrOfCombinaisons <= 0) {
            return false;
        }

        // Create new child to proceed
        $sId = (count(static::$workerSend) + 1);

        // Create new child to proceed
        static::$workerSend[ $sId ] = new \xPasswords\Child\Create([

            // React Loop
            'loop' => static::$reactLoop,

            // Type of child
            'type' => 'analysisSend',

            // Timeout
            'timeout' => 600, // 10 minutes

            // Header text
            'header' => 'Sending ' . $nbrOfCombinaisons . ' entri' . ($nbrOfCombinaisons > 1 ? 'es' : 'y'). ' to daemon...',

            // User custom defines
            'options' => [
                'title' => 'Network',
                'sId' => $sId,
            ]
        ]);
        static::$workerSend[ $sId ]->on('exit', function($thisProcess) use ($sId) {
            // Free memory
            unset(Client::$workerSend[ $sId ]); Client::$workerSend[ $sId ] = false;
        });

        static::$workerSend[ $sId ]->run();
    }

    // WebServer queue datas
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

            case 'pushBack': // Proceed returned results and insert back in the database
            echo Core::say('[NETWORK] [SUCCESS] Push back received.', ['color' => 'green']);

            // Begin inserting (10x faster than AUTOCOMMIT)
            Bootstrap::$Database->beginTransaction();

            foreach($datas['datas'] as $encryptedResult) {

                // Decrypt results
                $encryptedResult = Core::decode(Core::$Cipher->decrypt($encryptedResult['sDatas']));

                // Verify if pushed back datas is valid
                if(empty($encryptedResult['sId']) OR // sId verify
                   !ctype_digit((string) $encryptedResult['sId']) OR
                   empty($encryptedResult['password']) OR // Password verify
                   !is_bool($encryptedResult['wasAuthenticated']) OR // wasAuthenticated verify
                   !is_bool($encryptedResult['wasBruteforced'])) // wasBruteforced verify
                {
                    echo Core::say('[NETWORK] [ERROR] Problem while updating an entry. Something is corrupted.', ['color' => 'red']);
                    echo Core::say('[NETWORK] [ERROR] Details: ' . print_r($encryptedResult, true), ['color' => 'red']);
                    
                } else {

                    // Update the entry in database
                    echo Core::say('[NETWORK] [SUCCESS] Updating sId=' . $encryptedResult['sId'] . ' datas.', ['color' => 'green']);

                    // Update entry in database
                    $stmt = Bootstrap::$Database->prepare('UPDATE `xCombinaisons` SET `isBusy`=0, `wasVerified`=1,`isSuccess`=:isSuccess, `receivedTime`=:receivedTime, `sPassword`=:sPassword, `juicyInformations`=:juicyInformations WHERE `sId`=:sId');
                    $stmt->execute([
                        'isSuccess' => ($encryptedResult['wasAuthenticated'] ? 1 : 0),
                        'receivedTime' => Core::dateNow(),
                        'sPassword' => $encryptedResult['password'],
                        'juicyInformations' => (!$encryptedResult['juicyInformations'] ? 0 : Core::encode($encryptedResult['juicyInformations'])),
                        'sId' => $encryptedResult['sId'],
                    ]);
                }
            }

            // Commit in database
            Bootstrap::$Database->commit();
            
            $response->writeHead(200, Network::$HTTPResponseHeaders);
            $response->end(Core::compress(Core::$CipherNetwork->encrypt(Core::encode(['success' => true]))));
            return true;
            break;

            case 'declareWorker': // Declaring worker (saving URL and sending back useful informations like proxy etc)
            echo Core::say('[NETWORK] [SUCCESS] New worker declared.', ['color' => 'green']);
            $response->writeHead(200, Network::$HTTPResponseHeaders);
            
            // Save the worker
            $stmt = Bootstrap::$Database->prepare('INSERT INTO `xDeclaredWorkers`(`sAddress`, `sPublicIP`, `lastActivity`, `sStatus`) VALUES (:sAddress, :sPublicIP, :lastActivity, 1) ON DUPLICATE KEY UPDATE `sStatus`=1, `sPublicIP`=:sPublicIP, `lastActivity`=:lastActivity');
            $stmt->execute([
                'sAddress' => $datas['datas']['onionURL'],
                'sPublicIP' => $datas['datas']['sPublicIP'],
                'lastActivity' => Core::dateNow(),
            ]);
            
            // Get latest available providers list
            $stmt = Bootstrap::$Database->prepare('SELECT `sEmails`, `sClassName`, `sWorkingCombinaison` FROM `xProviders` WHERE `sStatus`=1');
            $stmt->execute();
            
            // Get latest available fresh socks list
            $stmtSocks = Bootstrap::$Database->prepare('SELECT `sPublicIP`, `sPort`, `sUsername`, `sPassword`, `sIdentifier` FROM `xSocks` WHERE `sStatus`=1');
            $stmtSocks->execute();
            $stmtSocks = $stmtSocks->fetchAll(\PDO::FETCH_ASSOC);
            if(empty($stmtSocks)) {
                echo Core::say('[SERVER] [WARNING] No socks are available, the server daemon will use its IP.', ['color' => 'yellow']);
            }
            
            // Return response with useful informations
            $response->end(
                Core::compress(
                    Core::$CipherNetwork->encrypt(
                        Core::encode(
                            [
                                'success' => true,
                                'availableSocks' => $stmtSocks,
                                'availableProviders' => $stmt->fetchAll(\PDO::FETCH_ASSOC),
                            ]
                        )
                    )
                )
            );
            
            $stmtSocks = NULL;
            $stmt = NULL;
            return true;
            break;
        }

        return false;
    }
};

Client::run();