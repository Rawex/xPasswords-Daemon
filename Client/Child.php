<?php
namespace xPasswords;

// Load dependencies
require('../Class/Core.php');
require('Payments.php');

// Child detection
if(!XPASSWORDS_IS_CHILDREN) {
    Core::selfSuicide(); // Bye bye !
}

class Child extends \xPasswords\Child\Base {

    private static $emailsContainer = [];
    
    protected static function updatePayments() {
        
        // Check if the signature is valid
        if(static::$inboundDatas['encryptionKey'] !== XPASSWORDS_CHILD_ENCRYPTION_KEY) {
            Core::selfSuicide();
        }
        
        // Login to database
        static::databaseConnect(XPASSWORDS_FILENAME_CLIENT);
        
        $updateStatus = function($sStatus, $sId) {
            
            // Update the status
            $stmt = Bootstrap::$Database->prepare('UPDATE xTransactions SET sStatus=:sStatus WHERE sId=:sId');
            $stmt->execute([
                'sStatus' => $sStatus,
                'sId' => $sId,
            ]);
            $stmt = NULL;

            return true;
        };

        // Get latest transactions
        $stmt = Bootstrap::$Database->prepare('SELECT `sId`, `sAddress`, `sStatus`, `sAmount`, `sExpireTime`, `sFromUserId`, `sLockedCurrencies` FROM `xTransactions` WHERE `sStatus`=0 OR `sStatus`=1');
        $stmt->execute();
        $xQuery = $stmt->fetchAll(\PDO::FETCH_ASSOC);
        
        //echo Core::say(print_r($xQuery, true));
        if(empty($xQuery)) {
            echo Core::say('[INFO] There is no new transactions to check.', [ 'color' => 'brown' ]);
            return false;
        }
        
        // Get the latest sId
        $lastSelectedId = end($xQuery)['sId'];

        foreach($xQuery as $balanceInformations) {

            echo Core::say('[INFO] Checking address ' . $balanceInformations['sAddress'] . '...', ['color' => 'brown']);
            
            // Sleep a bit
            Core::sleep(2);
            
            // Check if the transaction is not expired
            if(new \DateTime() > new \DateTime($balanceInformations['sExpireTime'])) {
                
                echo Core::say('[ERROR] The "' . $balanceInformations['sAddress'] . '" address is now expired.', ['color' => 'red']);

                // Set status as expired
                $updateStatus(XPASSWORDS_PAYMENTS_IS_EXPIRED, $balanceInformations['sId']);

                continue;
            }

            // Check for UNPAID and PAID
            // ToDo: Replace this by non-bloquant method
            switch($balanceInformations['sStatus']) {
                case XPASSWORDS_PAYMENTS_IS_UNPAID: // Check if the requested amount has been paid
                $checkBalance = Payments::checkBalanceOf($balanceInformations['sAddress'], 0);
                break;

                case XPASSWORDS_PAYMENTS_IS_PAID: // Get XPASSWORDS_PAYMENTS_IS_VERIFIED
                $checkBalance = Payments::checkBalanceOf($balanceInformations['sAddress'], 3);
                break;
            }

            // Check if the balance is numeric
            if(!is_numeric($checkBalance)) {
                echo Core::say('[ERROR] Error detected while checking balance !', ['color' => 'red']);
                echo Core::say('[ERROR] Details: ' . $checkBalance , ['color' => 'red']);
                continue;
            }
            
            // Check if the balance is not empty
            if($checkBalance <= 0) {

                switch($balanceInformations['sStatus']) {
                    case XPASSWORDS_PAYMENTS_IS_UNPAID: // Check if the requested amount has been paid
                    echo Core::say('[INFO] The "' . $balanceInformations['sAddress'] . '" balance is not paid yet.', ['color' => 'red']);
                    break;

                    case XPASSWORDS_PAYMENTS_IS_PAID: // Check if the requested amount has been paid
                    echo Core::say('[INFO] The "' . $balanceInformations['sAddress'] . '" balance is not verified yet.', ['color' => 'red']);
                    break;
                }

               continue;
            }

            /*if($balanceInformations['sAmount'] > Payments::convertToBTCFromSatoshi($checkBalance)) {
                echo Core::say('[ERROR] The "' . $balanceInformations['sAddress'] . '" balance received ' . Payments::convertToBTCFromSatoshi($checkBalance) . ' BTC, expected ' . $balanceInformations['sAmount'] . ' BTC.', ['color' => 'red']);

                continue;
            }*/

            // Check for UNPAID and PAID
            switch($balanceInformations['sStatus']) {

                case XPASSWORDS_PAYMENTS_IS_UNPAID: // Check if the requested amount has been paid
                echo Core::say('[SUCCESS] The "' . $balanceInformations['sAddress'] . '" balance looks like paid (' . Payments::convertToBTCFromSatoshi($checkBalance) . ' BTC), waiting for miners confirmations.', ['color' => 'green']);
                
                // Add 24 hours to the expiration and update it
                $stmt = Bootstrap::$Database->prepare('UPDATE `xTransactions` SET `sExpireTime`=:sExpireTime WHERE `sId`=:sId')->execute([
                    'sExpireTime' => (new \DateTime($balanceInformations['sExpireTime']))->modify('+1 day')->format('Y-m-d H:i:s'),
                    'sId' => $balanceInformations['sId'], // User ID
                ]);

                // Set status as paid
                $updateStatus(XPASSWORDS_PAYMENTS_IS_PAID, $balanceInformations['sId']);
                break;

                case XPASSWORDS_PAYMENTS_IS_PAID: // Get XPASSWORDS_PAYMENTS_IS_VERIFIED
                echo Core::say('[SUCCESS] The "' . $balanceInformations['sAddress'] . '" balance is now verified.', ['color' => 'green']);
                
                // Check sLockedCurrencies and used saved exchanges
                $balanceInformations['sLockedCurrencies'] = Core::decode($balanceInformations['sLockedCurrencies']);
                if(empty($balanceInformations['sLockedCurrencies'])) {

                    echo Core::say('[ERROR] Error while retrieving exchange for "' . $balanceInformations['sAddress'] . '" address, using updated one.', ['color' => 'red']);
                    
                    // Recupère l'échange actuel
                    $stmt = Bootstrap::$Database->prepare('SELECT `sExchange` FROM `xCurrencies` WHERE `sCurrency`=:sCurrency AND `sDestination`=:sDestination');
                    $stmt->execute([
                        'sCurrency' => 'BTC',
                        'sDestination' => 'EUR',
                    ]);
                    $sExchange = $stmt->fetch(\PDO::FETCH_ASSOC)['sExchange'];
                    $balanceInformations['sLockedCurrencies'] = [
                        'sExchange' => $sExchange,
                    ];
                    $stmt = NULL;
                }
                
                // Get credits of the user
                $stmt = Bootstrap::$Database->prepare('SELECT `sCreditsLeft` FROM `xAccounts` WHERE sId=:sId');
                $stmt->execute([
                    'sId' => $balanceInformations['sFromUserId'],
                ]);
                $sCreditsLeft = $stmt->fetch(\PDO::FETCH_ASSOC)['sCreditsLeft'];
                $sCreditsNew = round((Payments::convertToBTCFromSatoshi($checkBalance) * $balanceInformations['sLockedCurrencies']['sExchange']), 2, PHP_ROUND_HALF_DOWN);
                
                // Updating in database
                $stmt = Bootstrap::$Database->prepare('UPDATE `xAccounts` SET `sCreditsLeft`=sCreditsLeft + :sCreditsNew WHERE `sId`=:sFromUserId')->execute([
                    // Note: Divide per 1 if 1 EUR = how much btc needed
                    'sCreditsNew' => $sCreditsNew,
                    'sFromUserId' => $balanceInformations['sFromUserId'], // User ID
                ]);
                
                // Set amount added
                $stmt = Bootstrap::$Database->prepare('UPDATE xTransactions SET sAmount=:sAmount WHERE sId=:sId');
                $stmt->execute([
                    'sAmount' => $sCreditsNew,
                    'sId' => $balanceInformations['sId'],
                ]);
                
                // Set status as paid + verified
                $updateStatus(XPASSWORDS_PAYMENTS_IS_VERIFIED, $balanceInformations['sId']);
                break;
            }
        }

        $sStatusSet = NULL;
        $checkBalance = NULL;
        return true;   
    }

    protected static function analysisRefresher() {

        // Verify if the inboundDatas is correct
        if(!is_array(static::$inboundDatas)) {
            return false;
        }

        // Login to database
        static::databaseConnect(XPASSWORDS_FILENAME_CLIENT);

        // Do the job
        foreach(static::$inboundDatas as $xScanId) {

            $xQueryCountCombinaisons = [
                'all' =>        Bootstrap::$Database->prepare('SELECT COUNT(*) FROM `xCombinaisons` WHERE `xScanId`=:xScanId'),
                'verified' =>   Bootstrap::$Database->prepare('SELECT COUNT(*) FROM `xCombinaisons` WHERE `xScanId`=:xScanId AND `wasVerified`=1'),
                'success' =>    Bootstrap::$Database->prepare('SELECT COUNT(*) FROM `xCombinaisons` WHERE `xScanId`=:xScanId AND `wasVerified`=1 AND `isSuccess`=1'),
            ];

            // Execute them
            $xQueryCountCombinaisons['all']->execute([
                'xScanId' => $xScanId['sId']
            ]);            
            $xQueryCountCombinaisons['verified']->execute([
                'xScanId' => $xScanId['sId']
            ]);
            $xQueryCountCombinaisons['success']->execute([
                'xScanId' => $xScanId['sId']
            ]);

            // Set fetch mode
            $xQueryCountCombinaisons['all']->setFetchMode(\PDO::FETCH_NUM);
            $xQueryCountCombinaisons['verified']->setFetchMode(\PDO::FETCH_NUM);
            $xQueryCountCombinaisons['success']->setFetchMode(\PDO::FETCH_NUM);

            // Just get numbers
            $xQueryCountCombinaisons['all'] = $xQueryCountCombinaisons['all']->fetch()[0];
            $xQueryCountCombinaisons['verified'] = $xQueryCountCombinaisons['verified']->fetch()[0];
            $xQueryCountCombinaisons['success'] = $xQueryCountCombinaisons['success']->fetch()[0];

            // Recalculate percentage and set to finish status            
            $calculatedP = number_format($xQueryCountCombinaisons['verified'] / $xQueryCountCombinaisons['all'] * 100, 0);

            // Don't update if this is the same percentage as the database
            if(($xScanId['sPercentageVerified'] != $calculatedP) OR $xScanId['sPercentageVerified'] == 100) {

                // Updating in database
                $xUpdatePercentage = Bootstrap::$Database->prepare('UPDATE `xScanId` SET `sStatus`=:sStatus, `sPercentageVerified`=:sPercentageVerified, `sFinishTime`=:sFinishTime WHERE `sId`=:sId');
                $xUpdatePercentage->execute([
                    'sStatus' => ($xQueryCountCombinaisons['all'] == $xQueryCountCombinaisons['verified'] ? 3 : 2),
                    'sPercentageVerified' => $calculatedP,
                    'sFinishTime' => ($xQueryCountCombinaisons['all'] == $xQueryCountCombinaisons['verified'] ? Core::dateNow() : ''),
                    'sId' => $xScanId['sId'], // Scan ID
                ]);

                // Say it !
                echo Core::say('[REFRESHER] Scan #' . $xScanId['sId'] . ' has been updated. It is now at ' . $calculatedP . '%.', ['color' => 'green']);
            }
        }
    }
    
    // Update BTC exchange from preev.com
    protected static function updateExchange() {

        // Check if the signature is valid
        if(static::$inboundDatas['encryptionKey'] !== XPASSWORDS_CHILD_ENCRYPTION_KEY) {
            Core::selfSuicide();
        }

        // Login to database
        static::databaseConnect(XPASSWORDS_FILENAME_CLIENT);

        // Preev.com URLs
        $currenciesURLs = [
            'USD' => 'http://preev.com/pulse/units:btc+usd/sources:bitfinex+bitstamp+btce+localbitcoins',
            'EUR' => 'http://preev.com/pulse/units:btc+eur/sources:btce+kraken',
        ];

        try {

            $request = \Requests::get($currenciesURLs['EUR'], [

                'User-Agent' => Core::getUserAgent(),
                'Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language' => 'Accept-Language: fr-FR,fr;q=0.8,en-US;q=0.6,en;q=0.4',
                'Content-Type' => 'application/x-www-form-urlencoded',
                'Connection' => 'keep-alive',
            ], [

                'timeout' => XPASSWORDS_IO_TIMEOUT_OUT, // Timeout
                'proxy' => [
                    'type' => 'SOCKS5',
                    'authentication' => [
                        '127.0.0.1:9050'
                    ],
                ], // SOCKS Proxy
                'follow_redirects' => false, // Don't follow redirections
                'useragent' => Core::getUserAgent(), // Custom UA
            ]);

        } catch (\Exception $e) {
            echo Core::say('[ERROR] TOR network is unreachable. Make sure that the TOR network is correctly setup.', ['color' => 'red']);
            //echo Core::say($e->getMessage());
            return false;
        }

        // Check if the response is correctly in JSON
        if(!Core::isJSON($request->body)) {
            echo Core::say('[ERROR] Received invalid JSON !', ['color' => 'red']);
            return false;
        }

        // Decompress JSON into an array
        $datas = Core::decode($request->body);
        $request = NULL;

        // Calcule la moyenne
        // {"btc":{"eur":{"btce":{"last":412.0,"volume":130952.04},"kraken":{"last":422.3,"volume":904347.94}}},"other":{"slot":1398902400,"ver":"river"}}
        $xResult = 0;
        foreach($datas['btc']['eur'] as $current) {
            $xResult = $xResult + $current['last'];
        }
        $current = NULL;

        // Créer la moyenne
        $xResult = ($xResult / count($datas['btc']['eur']));

        // Rend le site hors ligne si il y a un Krach du cours
        $stmt = Bootstrap::$Database->prepare('SELECT `sExchange` FROM `xCurrencies` WHERE `sCurrency`=:sCurrency AND `sDestination`=:sDestination');
        $stmt->execute([
            'sCurrency' => 'BTC',
            'sDestination' => 'EUR',
        ]);
        $sExchange = $stmt->fetch(\PDO::FETCH_ASSOC)['sExchange'];

        // Krach du cours de minimum 40% ?
        if((round($sExchange) * ((100 - 40) / 100)) >= $xResult) {

            // Met le site hors ligne
            echo Core::say('Krach du cours Bitcoin détectée, la mise à jour du cours n’a pas été faite.', ['color' => 'red']);

            // Warn

        } else {

            // Update in database
            $stmt = Bootstrap::$Database->prepare('UPDATE `xCurrencies` SET `sExchange`=:sExchange, `sLastUpdate`=:sLastUpdate WHERE `sCurrency`=:sCurrency AND `sDestination`=:sDestination');
            $stmt->execute([
                'sExchange' => $xResult,
                'sLastUpdate' => Core::dateNow(),
                'sCurrency' => 'BTC',
                'sDestination' => 'EUR',
            ]);
        }

        // Say it !
        echo Core::say('Le cours actuel du Bitcoin est actuellement de ' . $xResult . ' EUR / BTC', ['color' => 'green']);
    }

    /*
    * Send filtered combinaisons to server daemon
    */
    protected static function analysisSend() {

        // Check if the signature is valid
        if(static::$inboundDatas['encryptionKey'] !== XPASSWORDS_CHILD_ENCRYPTION_KEY) {
            Core::selfSuicide();
        }

        // Login to database
        static::databaseConnect(XPASSWORDS_FILENAME_CLIENT);

        // Get all non-busy combinaisons
        $stmt = Bootstrap::$Database->prepare(
            'SELECT `xCombinaisons`.`sId`, `xCombinaisons`.`sEmail`, `xCombinaisons`.`sPassword`, `xScanId`.`sFor`, `xScanId`.`sAdvancedOptions`, `xScanId`.`sCountry`
             FROM `xCombinaisons`
             INNER JOIN `xScanId`
             ON `xScanId`.`sId`=`xCombinaisons`.`xScanId`
             WHERE `xCombinaisons`.`isBusy`=0
                AND `xCombinaisons`.`isSuccess`=0
                AND `xCombinaisons`.`wasVerified`=0
             ORDER BY `xCombinaisons`.`sId` ASC
             LIMIT 0, ' . XPASSWORDS_IO_CALLBACK_MAXRESULTSPERQUERY
        );
        $stmt->execute();
        $xQuery = $stmt->fetchAll(\PDO::FETCH_ASSOC);

        if(!empty($xQuery)) {

            // Set entries busy
            $dateNow = Core::dateNow();
            Bootstrap::$Database->beginTransaction();
            foreach($xQuery as $xEntry) {
                $stmt = Bootstrap::$Database->prepare('UPDATE `xCombinaisons` SET `isBusy`=1, `sentTime`=:sentTime WHERE `sId`=:sId');
                $stmt->execute([
                    'sId' => $xEntry['sId'],
                    'sentTime' => $dateNow,
                ]);
            }
            Bootstrap::$Database->commit();
            
            // Lets begin
            // Use beginTransations: If xPasswordsRequest fail, it will rollback to its original values
            Bootstrap::$Database->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
            Bootstrap::$Database->beginTransaction();

            try {
                
                // Send results over TOR
                if(!Request::make(XPASSWORDS_IO_SERVER_RACINE_URL, [
                    'cmd' => 'expressDelivery',
                    'datas' => $xQuery,
                ])) {
                    throw new \Exception(Request::$lastError);
                }
        
                // Update NUMBERS_OF_COMBINAISONS_SENT
                $stmt = Bootstrap::$Database->prepare('UPDATE `xStats` SET `sValue`=sValue + :sValue WHERE `sIdentifier`=:sIdentifier');
                $stmt->execute([
                    'sValue' => count($xQuery),
                    'sIdentifier' => 'NUMBERS_OF_COMBINAISONS_SENT',
                ]);

                echo Core::say('[INFO] All entries has been sent !', ['color' => 'green']);

            } catch (\Exception $e) {

                // Free entries
                Bootstrap::$Database->beginTransaction();
                foreach($xQuery as $xEntry) {
                    $stmt = Bootstrap::$Database->prepare('UPDATE `xCombinaisons` SET `isBusy`=0, `sentTime`=0 WHERE `sId`=:sId');
                    $stmt->execute([
                        'sId' => $xEntry['sId'],
                    ]);
                }
                Bootstrap::$Database->commit();
                
                echo Core::say('[ERROR] TOR network or Onion server is unreachable. Make sure that the TOR network is correctly setup.', ['color' => 'red']);
            }
        }
    }

    /*
    * Check pending analysis
    * Filter emails / passwords and calculate the cost
    */
    protected static function analysisCalculate() {
        
        // Set providers
        Core::$authenticationProviders = static::$inboundDatas['providers'];

        // Init vars
        $lastUpdatePercentage = TIME_RUN;        

        // Combinaison checker function
        $checkCombinaison = function($xQuery) {

            $accountCredentials = [
                'fullEmail' => $xQuery['sEmail'],
                'password' => $xQuery['sPassword'],
                'email' => false,
            ];

            // Vérifier si l'email est valide et correspond à un fournisseur valide
            // Vérifier si le mot de passe fait plus de 4 caractères
            // Vérifier si l'email ne contient pas un mot blacklisté
            // Vérifier si le mot de passe n'est pas faible (si c'est le cas cela veux dire que la boîte mail n'est pas importante ou qu'il y a de grandes chances que ça ne fonctionne pas)
            // Vérifier si le mot de passe n'est pas du sha1, md5, sha512 ou sha256
            // Vérifier si l'email n'est pas égal au mot de passe

            // Vérifier si l'email est valide et correspond à un fournisseur valide
            if(!filter_var($accountCredentials['fullEmail'], FILTER_VALIDATE_EMAIL)) {
                return ['success' => false, 'reason' => 'L’email est invalide'];
            }

            // Vérifier si l'email n'est pas double
            if(isset(static::$emailsContainer[ $accountCredentials['fullEmail'] ])) {
                return ['success' => false, 'reason' => 'L’email est un doublon'];
            }

            // Vérifier si l'email n'est pas le mot de passe
            if($accountCredentials['fullEmail'] == $accountCredentials['password']) {
                return ['success' => false, 'reason' => 'L’email ne peux être égal au mot de passe'];
            }
            
            // Add it to tested vars
            static::$emailsContainer[ $accountCredentials['fullEmail'] ] = true;

            // Explode email securely
            $accountCredentials['email'] = explode('@', $accountCredentials['fullEmail']);

            // Blacklist words checker
            try {

                foreach(Constants::$authenticationBlacklistedWords as
                        $word => $articles) {

                    // Test if something can be found with the whole word
                    // Verify at the beggining and the end
                    if(preg_match('/^' . $word . '/iu', $accountCredentials['email'][0]) OR preg_match('/' . $word . '$/iu', $accountCredentials['email'][0])) {
                        throw new \Exception($word);
                        break;
                    }

                    // Try to detect with articles (french only supported atm)
                    $articles = Constants::$authenticationBlacklistedWordsDefaults[$articles];
                    foreach($articles as $article) {
                        // Verify ONLY at the beggining
                        if(preg_match('/^' . $article . $word . '/iu', $accountCredentials['email'][0])) {
                            throw new \Exception($article . $word);
                            break;
                        }
                    }
                }
            } catch (\Exception $e) {
                return ['success' => false, 'reason' => 'L’email contient des mots interdits (' . $e->getMessage() . ')'];
            }

            // Detect if the password is not empty
            if(empty($accountCredentials['password'])) {
                return ['success' => false, 'reason' => 'Le mot de passe est vide'];
            }

            // Detect the password complexity
            if(strlen($accountCredentials['password']) <= 4) {
                return ['success' => false, 'reason' => 'Le mot de passe est trop court'];
            }

            // Detect if the password is not weak
            if(in_array(strtolower($accountCredentials['password']), Constants::$passwordsBlacklisted)) {
                return ['success' => false, 'reason' => 'Le mot de passe est trop faible'];
            }

            // Detect if this provider is available
            $accountCredentials['provider'] = Core::providerCheck($accountCredentials['email'][1]);
            if($accountCredentials['provider'] === false) {
                return ['success' => false, 'reason' => 'Ce fournisseur n’est pas encore supporté'];
            }

            return ['success' => true];
        };

        // Login to database
        static::databaseConnect(XPASSWORDS_FILENAME_CLIENT);

        // Check combinaisons for this entry
        try {

            // Retrieve pending combinaisons (not filtered yet) only for this user
            $stmt = Bootstrap::$Database->prepare('SELECT `sId`, `xScanId`, `sEmail`, `sPassword`, `sStatus` FROM xCombinaisonsPending WHERE xScanId=:xScanId AND sStatus=0');
            $stmt->execute([
                'xScanId' => static::$inboundDatas['scan']['sId'],
            ]);
            $xQueries = $stmt->fetchAll(\PDO::FETCH_ASSOC);

        } catch (\Exception $e) {
            static::returnResponse(false);
            return false;
        }

        // Skip verification if there is nothing new
        if(empty($xQueries)) {
            return false;
        }

        // Counter (for percentage)
        $xQueryCount = [
            'all' => count($xQueries),
            'incrementerAll' => 0,
            'rejected' => 0,
        ];

        // Begin inserting (10x faster than AUTOCOMMIT)
        Bootstrap::$Database->beginTransaction();

        foreach($xQueries as $xQuery) {

            // Increment entry
            $xQueryCount['incrementerAll']++;

            // Set email lowercase
            $xQuery['sEmail'] = strtolower($xQuery['sEmail']);

            // Verify this entry
            $sDatas = $checkCombinaison($xQuery);

            // Check percentage
            if(($lastUpdatePercentage < time()) === true) {

                // Update the percentage
                $calculatedP = number_format($xQueryCount['incrementerAll'] / $xQueryCount['all'] * 100, 0);
                static::returnResponse($calculatedP, 'setPercentage');

                // Say it !
                echo Core::say('[INFO] Pre-analysis scan: ' . $xQueryCount['incrementerAll'] . '/' . $xQueryCount['all'] . ' entries checked (' . $calculatedP . '%)', ['color' => 'green']);

                // Setting the cache when saving data
                $lastUpdatePercentage = (time() + 2);

                // Destroy vars
                $calculatedP = NULL;
            }
            
            switch($sDatas['success']) {
                case false: // Increment rejected combinaisons
                $xQueryCount['rejected']++;
                break;
            }
            
            // Update the entry in database
            $stmt = Bootstrap::$Database->prepare('UPDATE `xCombinaisonsPending` SET `sEmail`=:sEmail, `sStatus`=:sStatus, `sReason`=:sReason WHERE `sId`=:sId');
            $stmt->execute([
                'sEmail' => $xQuery['sEmail'], // Already strtolowed
                'sStatus' => ($sDatas['success'] ? 1 : 2), // 0 = no-verified, 1 = valid, 2 = invalid
                'sReason' => (isset($sDatas['reason']) ? $sDatas['reason'] : ''),
                'sId' => $xQuery['sId'],
            ]);
            $sDatas = NULL;
        }
        
        // Update NUMBERS_OF_COMBINAISONS_FILTERED
        $stmt = Bootstrap::$Database->prepare('UPDATE `xStats` SET `sValue`=sValue + :sValue WHERE `sIdentifier`=:sIdentifier');
        $stmt->execute([
            'sValue' => $xQueryCount['all'],
            'sIdentifier' => 'NUMBERS_OF_COMBINAISONS_FILTERED',
        ]);
        
        // Update NUMBERS_OF_COMBINAISONS_REJECTED
        if($xQueryCount['rejected'] > 0) {
            $stmt = Bootstrap::$Database->prepare('UPDATE `xStats` SET `sValue`=sValue + :sValue WHERE `sIdentifier`=:sIdentifier');
            $stmt->execute([
                'sValue' => $xQueryCount['rejected'],
                'sIdentifier' => 'NUMBERS_OF_COMBINAISONS_REJECTED',
            ]);
        }

        // Now commit
        Bootstrap::$Database->commit();

        // Calculate the cost
        $calculateCost = function($initialValues=[]) {

            // Get prices
            $dbGet = Bootstrap::$Database->prepare('SELECT `sIdentifier`, `sPrice` FROM xPricing');
            $dbGet->execute();
            $dbGet = $dbGet->fetchAll(\PDO::FETCH_OBJ);

            // Calculate price here
            $fPrice = [];
            foreach($dbGet as $iterator => $datas) {
                if(isset($initialValues[ $datas->sIdentifier ])) {
                    $fPrice[ $datas->sIdentifier ] = round(($initialValues[ $datas->sIdentifier ] * $datas->sPrice), 3, PHP_ROUND_HALF_UP);
                }
            }

            // Ensure everything was calculated
            if(count($fPrice) != count($initialValues)) {
                return []; 
            }

            return $fPrice;
        };

        // Get all valid entries
        $stmd = Bootstrap::$Database->prepare('SELECT COUNT(`sId`) FROM xCombinaisonsPending WHERE xScanId=:xScanId AND sStatus=1');
        $stmd->execute([
            'xScanId' => static::$inboundDatas['scan']['sId'],
        ]);
        $xSuccessCombinaisons = $stmd->fetchAll(\PDO::FETCH_ASSOC);
        $xSuccessCombinaisons = $xSuccessCombinaisons[0]['COUNT(`sId`)'];

        // Set the scan to 0% and switch to payment status
        $stmt = Bootstrap::$Database->prepare('UPDATE `xScanId` SET `sStatus`=1, `sPercentageVerified`=0, `sCost`=:sCost WHERE `sId`=:sId');
        $stmt->execute([
            'sCost' => Core::encode($calculateCost(
                [
                    'PRICE_PER_COMBINAISONS' => $xSuccessCombinaisons,
                    'PRICE_PER_SERVICES' => ($xSuccessCombinaisons * count(Core::decode(static::$inboundDatas['scan']['sFor']))),
                    'PRICE_PER_ADVANCEDOPTIONS' => ($xSuccessCombinaisons * count(Core::decode(static::$inboundDatas['scan']['sAdvancedOptions']))),
                ]
            )),
            'sId' => static::$inboundDatas['scan']['sId'],
        ]);
        $stmt = NULL;

        // Say it ! 
        echo Core::say('[INFO] The #' . static::$inboundDatas['scan']['sId'] . ' pre-scan is finished !', ['color' => 'green']);

        // Set the scan to 0% and switch to payment status
        //static::returnResponse(false);

        // Reset vars and close SQL connection
        $xQueryCount = NULL;
        Bootstrap::$Database = NULL;

        return true;
    }
};

Child::run();