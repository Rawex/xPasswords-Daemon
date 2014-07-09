<?php

namespace xPasswords;

// Common defines
define('XPASSWORDS_VERSION', '0.71');
define('CRLF', "\r\n");
define('CRCRLF', "\r\r\n");
define('TIME_RUN', (int) time());
define('CURRENT_DIR', dirname(__FILE__));

// I/O Parameters
define('XPASSWORDS_IO_CALLBACK_RACINE_URL', 'kvhb3o72lpnmux7m.onion');
define('XPASSWORDS_IO_CALLBACK_MAXRESULTSPERQUERY', 10000);
define('XPASSWORDS_IO_SERVER_RACINE_URL', 'xl3eg66hzu6poclp.onion');
define('XPASSWORDS_IO_USERAGENT', 'xPasswords/' . XPASSWORDS_VERSION);
define('XPASSWORDS_IO_TIMEOUT_IN', 60); // Timeout IN (for the HTTP webserver)
define('XPASSWORDS_IO_TIMEOUT_OUT', 60); // Timeout OUT (for Requests class)

// Listen IP / Port parameters
define('XPASSWORDS_LISTEN_IP', '127.0.0.1');
define('XPASSWORDS_SERVER_LISTEN_PORT', 42510);
define('XPASSWORDS_CLIENT_LISTEN_PORT', 42511);

// Client password parameters
define('XPASSWORDS_CLIENT_DATABASE_PASSWORD', 'root');

// Payments informations
define('XPASSWORDS_PAYMENTS_IS_UNPAID', 0);
define('XPASSWORDS_PAYMENTS_IS_PAID', 1);
define('XPASSWORDS_PAYMENTS_IS_VERIFIED', 2);
define('XPASSWORDS_PAYMENTS_IS_EXPIRED', 3);

// Filenames restrictions
define('XPASSWORDS_FILENAME_SERVER', 'Server.php');
define('XPASSWORDS_FILENAME_CLIENT', 'Client.php');
define('XPASSWORDS_FILENAME_CHILD', 'Child.php');
define('XPASSWORDS_IS_CLIENT', ((basename($_SERVER['PHP_SELF']) == XPASSWORDS_FILENAME_CLIENT AND basename($_SERVER['SCRIPT_NAME']) == XPASSWORDS_FILENAME_CLIENT AND basename($_SERVER['SCRIPT_FILENAME']) == XPASSWORDS_FILENAME_CLIENT AND basename($_SERVER['PATH_TRANSLATED']) == XPASSWORDS_FILENAME_CLIENT) ? true : false));
define('XPASSWORDS_IS_SERVER', ((basename($_SERVER['PHP_SELF']) == XPASSWORDS_FILENAME_SERVER AND basename($_SERVER['SCRIPT_NAME']) == XPASSWORDS_FILENAME_SERVER AND basename($_SERVER['SCRIPT_FILENAME']) == XPASSWORDS_FILENAME_SERVER AND basename($_SERVER['PATH_TRANSLATED']) == XPASSWORDS_FILENAME_SERVER) ? true : false));
define('XPASSWORDS_IS_CHILDREN', (($_SERVER['PHP_SELF'] == XPASSWORDS_FILENAME_CHILD AND $_SERVER['SCRIPT_NAME'] == XPASSWORDS_FILENAME_CHILD AND $_SERVER['SCRIPT_FILENAME'] == XPASSWORDS_FILENAME_CHILD AND $_SERVER['PATH_TRANSLATED'] == XPASSWORDS_FILENAME_CHILD) ? true : false));

// Encryption and hashing settings here
define('XPASSWORDS_IO_NETWORK_KEY', 'PUT_RANDOM_CHARS_HERE');
define('XPASSWORDS_CHILD_ENCRYPTION_KEY', 'PUT_RANDOM_CHARS_HERE');

// Essential defines
class Constants {

    // Search criterias
    // Firsts values in key = most revelant
    static public $searchQueriesName = [
        
        // Sites de paiements en ligne
        '0' => [
            '0' => 'PayPal',
            '1' => 'iTunes',
            '2' => 'Amazon',
            '3' => 'Allopass',
            '4' => 'Starpass',
        ],
        
        // Possibles cartes bleues et compte bancaires
        '1' => [
            '0' => 'Possible credit card informations disclosure',
            '1' => 'Possible banking informations disclosure',
        ],
        
        // Possibles CNI et avis d’imposition
        '2' => [
            '0' => 'Possible identity card disclosure',
            '1' => 'Possible Tax Notice (Avis d\'imposition) disclosure',
        ],
        
        // Sites de jeux en ligne
        '3' => [
            '0' => 'Steam',
            '1' => 'Ubisoft',
            '2' => 'Riot Games (League Of Legends)',
            '3' => 'Blizzard (World of Warcraft, Diablo III, Starcraft, Heartstone)',
            '4' => 'NCSoft',
            '5' => 'Dofus',
        ],
        
        // Sites de monnaie virtuelle
        '4' => [
            '0' => 'Virwox',
            '1' => 'Coinbase',
            '2' => 'BlockChain',
        ],
        
        // Fournisseurs d'hébergement
        '5' => [
            '0' => 'OVH',
            '1' => 'Online.net',
        ],
        
        // Réseaux sociaux
        '6' => [
            '0' => 'Twitter',
            '1' => 'Tumblr',
        ],
        
        // Sites pour développeurs
        '7' => [
            '0' => 'GitHub',
            '1' => 'Gitorious',
            '2' => 'Bitbucket',
            '3' => 'CloudFlare',
        ],
        
        // Services de stockage / Streaming
        '8' => [
            '0' => 'MixtureCloud',
            '1' => 'Purevid',
        ],
        
        // Fournisseurs VPN
        '9' => [
            '0' => 'PrivateInternetAccess',
            '1' => 'GoldenFrog VyprVPN',
        ],
    ];

    static public $searchQueries = [

        // Sites de paiements en ligne
        0 => [

            // Paypal
            0 => [
                // France
                'FROM "service@paypal.fr"',
                'FROM "paypal@e.paypal.fr"',

                // Europe
                'FROM "service@paypal.co.uk"',
                'FROM "service@paypal.nl"',
                'FROM "service@paypal.de"',

                // Others
                'FROM "service@paypal.com"',
                'FROM "cs_surveys@paypal-customerfeedback.com"',
            ],
            // iTunes
            1 => [
                'FROM "do_not_reply@itunes.com"',  
            ],
            // Amazon
            2 => [
                'FROM "commandes@amazon.fr"',
                'FROM "store-news@amazon.fr"',
                'FROM "store-news@amazon.com"',
                'FROM "confirmation-commande@amazon.fr"',
            ],
            // Allopass
            3 => [
                'FROM "contact@allopass.com"',
            ],
            // Starpass
            4 => [
                'FROM "contact@starpass.fr"',
            ],
        ],

        // Possibles cartes bleues et compte bancaires
        1 => [
            // Possible credit card informations disclosure
            0 => [
                // Searching for credit card
                'BODY "VISA"',
                'BODY "MASTERCARD"',
                'BODY "AMEX"',
                //'BODY "cb "',
                //'BODY "paiement"',
            ],
            // Possible banking informations disclosure
            1 => [
                // Searching for banks accounts
                'BODY "La Banque Postale "',
                'BODY "CIC "',
                'BODY "LCL "',
                'BODY "BNP Paribas "',
                'BODY "HSBC "',
            ],
        ],

        // Possibles CNI et avis d’imposition
        2 => [
            // Possible identity card disclosure
            0 => [
                // Searching for CNI
                'BODY "carte d\'identité"',
                'BODY "carte d\'identite"',
            ],
            // Possible Tax Notice (Avis d\'imposition) disclosure
            1 => [
                'BODY "avis d\'imposition"',
                'BODY "tax notice"',
            ],
        ],

        // Sites de jeux en ligne
        3 => [
            // Steam
            0 => [
                'FROM "noreply@steampowered.com"',
            ],
            // Ubisoft
            1 => [
                'FROM "ubishop.support@ubisoft.com"',
                'FROM "AccountSupport@ubi.com"',
            ],
            // League Of Legends
            2 => [
                'FROM "accounts@riotgames.com"',
                'FROM "noreply@email.leagueoflegends.com"',
                'FROM "Leagueoflegends@email.riotgames.com"',
                'FROM "support@riotgames.zendesk.com"',
            ],
            // Blizzard
            3 => [
                'FROM "noreply@battle.net"',
                'FROM "noreplyeu@blizzard.com"',
                'FROM "Newsletter@email.blizzard.com"',
            ],
            // NCSoft
            4 => [
                'FROM "support@ncsoft.com"',
                'FROM "wildstarsupport@carbinestudios.com"',
            ],
            // Dofus
            5 => [
                'FROM "noreply@ankama.com"',
            ],
        ],

        // Sites de monnaie virtuelle
        4 => [
            // Virwox
            0 => [
                'FROM "register@virwox.com"',
            ],
            // Coinbase
            1 => [
                'FROM "contact@coinbase.com"',  
            ],
            // BlockChain
            2 => [
                'FROM "wallet@blockchain.info"',
            ],
        ],

        // Fournisseurs d'hébergement
        5 => [
            // OVH
            0 => [
                'FROM "support@ovh.com"',  
            ],
            // Online.net
            1 => [
                'FROM "support@online.net"',  
            ],
        ],

        // Réseaux sociaux
        6 => [
            // Twitter
            0 => [
                'FROM "info@twitter.com"',  
            ],
            // Tumblr
            1 => [
                'FROM "no-reply@tumblr.com"',  
            ],
        ],

        // Sites pour développeurs
        7 => [
            // GitHub
            0 => [
                'FROM "notifications@github.com"',
                'FROM "support@github.com"',
            ],
            // Gitorious
            1 => [
                'FROM "no-reply@gitorious.org"',
            ],
            // Bitbucket
            2 => [
                'FROM "noreply@bitbucket.org"',
            ],
            // CloudFlare
            3 => [
                'FROM "support@cloudflare.com"',
            ],
        ],

        // Services de stockage / Streaming
        8 => [
            // MixtureCloud
            0 => [
                'FROM "no-reply@mixturecloud.com"'
            ],
            // Purevid
            1 => [
                'FROM "support@purevid.com"',
            ],
        ],

        // Fournisseurs VPN
        9 => [
            // PrivateInternetAccess
            0 => [
                'FROM "helpdesk@privateinternetaccess.com"',
            ],
            // GoldenFrog VyprVPN
            1 => [
                'FROM "support@goldenfrog.com"',              
            ],
        ],
    ];

    // Blacklisted words array
    static public $authenticationBlacklistedWordsDefaults = [
        'feminin' => ['la', 'une', 'des', 'les'],
        'masculin' => ['le', 'un', 'des', 'les'],
        'others' => ['le', 'un', 'du'],
    ];
    static public $authenticationBlacklistedWords = [
        'passif' => 'masculin',
        'actif' => 'masculin',
        'lesbienne' => 'feminin',
        'gay' => 'masculin',
        'bite' => 'feminin',
        'suceur' => 'masculin',
        'suceuse' => 'feminin',
        'salope' => 'feminin',
        'pute' => 'feminin',
        'porn' => 'others',
        'dominateur' => 'masculin',
        'dominatrice' => 'feminin',
        'coquin' => 'masculin',
        'coquine' => 'feminin',
        'sexe' => 'masculin',
    ];

    // Remember that passwords less than 5 characters are ignored
    static public $passwordsBlacklisted = [
        // Common words
        'bonjour',
        'hello',
        'salut',
        'azerty',
        'motdepasse',
        'password',

        // Sex words
        'sexe123',
        '123sexe',
        'gay123',
        '123gay',

        // Tests words
        'test123',
        '123test',
        'lol123',
        '123lol',

        // Numbers
        '0000000',
        '000000',
        '00000',
        '12345',
        '123456',
        '123123',
    ];
};