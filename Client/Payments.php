<?php
namespace xPasswords;

class Payments {

    /** Verify if the payment is made */
    public static function checkBalanceOf($thisWallet=false, $confirmationsNumbers=6) {

        if(!$thisWallet) return false;

        try {

            $request = \Requests::get('https://blockchain.info/fr/q/getreceivedbyaddress/' . $thisWallet . '?confirmations=' . $confirmationsNumbers, [
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

        } catch (Exception $e) {
            echo Core::say('[ERROR] TOR network is unreachable. Make sure that the TOR network is correctly setup.', ['color' => 'red']);
            echo Core::say('[ERROR] Details: ' . $e->getMessage(), ['color' => 'red']);
            return false;
        }

        return (int) intval($request->body);
    }

    /** Convert Satoshis to a string that can be displayed to users.
    *  input: $value Integer or string that can be parsed as an int.
    *  output: string (eg: "1.00400000")
    */
    public static function convertToBTCFromSatoshi($value) {
        return (float) bcdiv(intval($value), 100000000, 8);
    }
};