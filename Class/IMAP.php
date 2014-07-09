<?php
/**
*
* Proprietary FIRST PHP class who support IMAP without imap_open 
*
* // Commands: http://stackoverflow.com/questions/10267500/libcurl-and-imap
* // HowTo: curl -u 'levihere@yahoo.com:' -X "EXAMINE INBOX" --url 'imaps://imap.mail.yahoo.com:993/INBOX'
*
* // What cIMAP have that imap_open don't
* // - Beautiful interface
* // - Proxy support
* // - Search criterias correctly working
*
**/
class cIMAP {

    public $errno;
    public $errstr;
    private $curl_handle;
    public $lastError;

    private $curl_options = [
        CURLOPT_TIMEOUT => 30,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_BINARYTRANSFER => true,
        CURLOPT_HEADER => true,
        CURLOPT_SSL_VERIFYPEER => false, // More speed but less security
    ];

    function __construct($options) {
        
        // Defines
        $this->lastError = false;
        $this->getCapability = false;
        
        // Init connection
        $this->curl_handle = curl_init();
        
        // Set default options
        curl_setopt_array($this->curl_handle, $this->curl_options);
        
        // Find if IMAPS or IMAP have to be used
        switch(strtolower(explode('://', $options['hostname'])[0])) {
            case 'imaps':
            curl_setopt($this->curl_handle, CURLOPT_PROTOCOLS, CURLPROTO_IMAPS);
            break;
           
            case 'imap':
            curl_setopt($this->curl_handle, CURLOPT_PROTOCOLS, CURLPROTO_IMAP);
            break;
            
            default:
            $this->lastError = ['error' => 'UNKNOWN_PROTOCOL', 'details' => 'Internal cIMAP error, protocol is unknown'];
            return false; // Unknown protocol
            break;
        }

        // User hostname and credientials
        curl_setopt($this->curl_handle, CURLOPT_URL, rtrim($options['hostname'], '/') . '/INBOX');
        curl_setopt($this->curl_handle, CURLOPT_USERPWD, $options['username'] . ':' . $options['password']);
        
        // Proxy support
        if(isset($options['proxy'])) {
            
            curl_setopt($this->curl_handle, CURLOPT_PROXYTYPE, 7);
            
            // One or more parameters passed ?
            if(is_array($options['proxy']['authentication'])) {
                curl_setopt($this->curl_handle, CURLOPT_PROXY, $options['proxy']['authentication'][0]);
                curl_setopt($this->curl_handle, CURLOPT_PROXYAUTH, CURLAUTH_ANY);
                curl_setopt($this->curl_handle, CURLOPT_PROXYUSERPWD, $options['proxy']['authentication'][1] . ':' . $options['proxy']['authentication'][2]);
            } else {
                
                // Only one parameter passed, the hostname of course !
                curl_setopt($this->curl_handle, CURLOPT_PROXY, $options['proxy']['authentication']);
            }
        }
        
        // Shuffle request time
        sleep(rand(0.1, 0.9));

        // Check if the authentication is okay
        $this->listFolders = $this->listFolders();
        if(!empty($this->listFolders)) {
            // Get capability
            $this->getCapability = $this->execCmd('CAPABILITY');
            $this->getCapability = (!empty($this->getCapability) ? array_change_key_case(array_values(explode(' ', trim(ltrim($this->getCapability, '* CAPABILITY')))), CASE_UPPER) : false);
            return true;
        }
        
        $this->lastError = trim(curl_error($this->curl_handle));

        if(preg_match('/^Authentication failed/u', $this->lastError)) {
            $this->lastError = ['error' => 'AUTH_FAILED', 'details' => $this->lastError];
            return false;
        }
        
        $this->lastError = ['error' => 'UNKNOWN', 'details' => $this->lastError];
        return false;
    }
    
    // Get server capability
    public function getCapability() {
        return $this->getCapability;
    }    
    public function hasCapability($query) {
        return in_array(strtoupper($query), $this->getCapability);   
    }
    
    public function getLastErr() {
        return $this->lastError;
    }

    private function execCmd($query) {
        curl_setopt($this->curl_handle, CURLOPT_CUSTOMREQUEST, $query);
        $output = curl_exec($this->curl_handle);
        
        if(curl_exec($this->curl_handle) === false) {
            $this->lastError = curl_error($this->curl_handle);
            return false;
        }
        
        return trim($output);
    }
    
    // Search function
    public function search($query, $options=[]) {
        
        //$commandName = ($this->hasCapability('ESEARCH') ? 'ESEARCH' : 'SEARCH');
        $commandName = 'SEARCH';
        
        $searchResult = $this->execCmd($commandName . ' ' . $query);
                
        // Detect if at least one message is found
        if(!$searchResult) {
            return false;
        }
        
        // Detect possible errors
        if(strtoupper(substr($searchResult, 0, 9)) != '* ' . $commandName . ' ') {
            return false;
        }
        
        // Sanitize and transform results into an array
        $searchResult = trim(ltrim($searchResult, '* ' . $commandName . ' '));
        $searchResult = explode(' ', $searchResult);
        
        // Return results
        return $searchResult;
    }
    
    // List folders function
    /* * LIST (\HasNoChildren) "/" "INBOX"
    * LIST (\Noselect \HasChildren) "/" "[Gmail]"
    * LIST (\HasNoChildren \Drafts) "/" "[Gmail]/Brouillons"
    * LIST (\HasNoChildren \Trash) "/" "[Gmail]/Corbeille"
    * LIST (\HasNoChildren \Important) "/" "[Gmail]/Important"
    * LIST (\HasNoChildren \Sent) "/" "[Gmail]/Messages envoy&AOk-s"
    * LIST (\HasNoChildren \Junk) "/" "[Gmail]/Spam"
    * LIST (\HasNoChildren \Flagged) "/" "[Gmail]/Suivis"
    * LIST (\HasNoChildren \All) "/" "[Gmail]/Tous les messages"" */
    public function listFolders() {
        
        $listFolder = $this->execCmd('LIST "*" "*"');
        if(empty($listFolder)) {
            // Using another method to list
            $listFolder = $this->execCmd('LIST "" "%"');
        }
        
        // Get mailboxes proprely
        preg_match_all('/\* LIST \((.*?)\) "(.*?)" "(.*?)"(?:\r\n)/iu', $listFolder, $listFolderArr);
        
        // Transform into an array        
        $listFolderMatches = [];
        foreach($listFolderArr[3] as $folderID => $folderName) {
            if(preg_match('/HasChildren/iu', $listFolderArr[1][$folderID])) {
                continue;
            }
            $listFolderMatches[$folderID] = $folderName;
        }
        
        return $listFolderMatches;
    }
        
    /* string(239) "* FLAGS (\Answered \Flagged \Draft \Deleted \Seen $Phishing $NotPhishing)
    * OK [PERMANENTFLAGS ()] Flags permitted.
    * OK [UIDVALIDITY 2] UIDs valid.
    * 0 EXISTS
    * 0 RECENT
    * OK [UIDNEXT 2] Predicted next UID.
    * OK [HIGHESTMODSEQ 4557]" */
    public function selectFolder($query, $readOnly = false) {
        // Select a new folder
        $selectFolder = ($readOnly ? $this->execCmd('EXAMINE "' . $query . '"') : $this->execCmd('SELECT "' . $query . '"'));
        
        if(empty($selectFolder)) {
            return false;
        }
        
        // Get number of mails in this mailbox proprely
        preg_match('/\* (.*?) EXISTS(?:\r\n)/iu', $selectFolder, $selectFolderArr);
        
        return $selectFolderArr[1];
    }
    
    public function disconnect() {
        
        // Close normally the connection
        $this->execCmd('LOGOUT');
        @curl_close($this->curl_handle);
        
        return true;
    }
};