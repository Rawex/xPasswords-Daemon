<?php

namespace xPasswords\Child;
use xPasswords as _Parent;

class Base {

    protected static $inboundDatas = false;
    protected static $childTypesBlacklisted = [
        'returnResponse', 'databaseConnect', 'run',
    ];

    // Return response to parent
    public static function returnResponse($inboundDatas, $type='results') {
        echo _Parent\Core::$Cipher->encrypt(_Parent\Core::encode([
            'type' => $type,
            'childOutput' => $inboundDatas
        ])) . CRLF;
    }

    public static function databaseConnect($type) {
        // Login to database
        if(!_Parent\Bootstrap::DatabaseConnect($type)) {
            echo _Parent\Core::say('[ERROR] Unable to connect to the database.', ['color' => 'red']);
            exit(0);
        }
    }

    // Execute a child
    public static function run() {

        $childType = _Parent\Core::getVar('childType');

        if(!method_exists('\xPasswords\Child', $childType)) {
            _Parent\Core::selfSuicide(); // Bye bye !   
        }

        // Blacklisted functions
        if(in_array($childType, static::$childTypesBlacklisted)) {
            _Parent\Core::selfSuicide(); // Bye bye !   
        }

        // Okay childType requested is valid, get inbound datas
        $inboundDatas = _Parent\Core::getVar('inboundDatas');

        // Prevent empty inboundDatas
        if(empty($inboundDatas)) {
            return false;
        }

        // Decrypt input
        try {
            $inboundDatas = _Parent\Core::$Cipher->decrypt($inboundDatas);
        } catch(\Exception $e) {
            _Parent\Core::selfSuicide(); // Bye bye !
        }

        // Check if the decryption has been correctly made
        if(!_Parent\Core::isJSON($inboundDatas)) {
            _Parent\Core::selfSuicide(); // Bye bye !
        }

        // Set inbound datas
        static::$inboundDatas = _Parent\Core::decode($inboundDatas);

        // Execute the appropriate action
        static::$childType();

        return true;
    }
};

class Create {

    public $process;
    private $loop;
    public $vars;
    private $onDatas;

    public function __construct($vars=[]) {
        
        // Prevent empty configuration
        if(empty($vars)) {
            return false;
        }

        // Set vars
        $this->on['exit'] = false;
        $this->on['start'] = false;
        $this->vars = $vars;

        // Prevent misconfigured inputs
        // Check isset + empty
        // Check loop is object
        if((!isset($this->vars['loop']) OR empty($this->vars['loop'])) OR
           (!isset($this->vars['type']) OR empty($this->vars['type']))) {
            echo _Parent\Core::say('[ERROR] Error in child configuration, please fix it.', ['color' => 'red']);
            exit(0);
        }

        // Payload default is the encrypted private key
        if((!isset($this->vars['payload']) OR empty($this->vars['payload']))) {
            $this->vars['payload'] = ['encryptionKey' => XPASSWORDS_CHILD_ENCRYPTION_KEY];
        }

        // Build text prepend
        $this->vars['options']['__textPreprend'] = '';
        if(isset($this->vars['options']['title']) AND !empty($this->vars['options']['title'])) {
            $this->vars['options']['__textPreprend'] .= '[' . strtoupper($this->vars['options']['title']) . '] ';
        }
        if(isset($this->vars['options']['sId']) AND !empty($this->vars['options']['sId'])) {
            $this->vars['options']['__textPreprend'] .= '[#' . $this->vars['options']['sId'] . '] ';
        }
        $this->vars['options']['__textPreprend'] .= '[CHILD]';

        // Set loop
        $this->loop =  $this->vars['loop'];
        $this->vars['loop'] = NULL;
        
        // Encrypt Payload and create process
        try {
            // var_dump('php Child.php --childType="' . $this->vars['type'] . '" --inboundDatas="'. _Parent\Core::$Cipher->encrypt(_Parent\Core::encode($this->vars['payload'])) . '"');
            $this->process = new \React\ChildProcess\Process('php Child.php --childType="' . $this->vars['type'] . '" --inboundDatas="'. _Parent\Core::$Cipher->encrypt(_Parent\Core::encode($this->vars['payload'])) . '"' . (_Parent\Core::getVar('with-compression') === 'true' ? ' --with-compression=true' : ''));
        } catch (\Exception $e) {
            echo _Parent\Core::say('[ERROR] Unable to encrypt datas for children ! Exiting...', ['color' => 'purple']);
            exit(0);
        }

        return true;
    }

    // Actions handling
    public function on($for=NULL, $arg=NULL) {
        $this->onDatas[ $for ] = $arg;
    }

    public function run() {

        // Mirroir this process
        $thisProcess = $this;

        // Set header text (if defined)
        if(isset($this->vars['header']) AND !empty($this->vars['header'])) {
            echo _Parent\Core::say($thisProcess->vars['options']['__textPreprend'] . ' [INFO] ' . $thisProcess->vars['header'], ['color' => 'purple']);
        }

        // Set onTimeout callback
        // Prevent possible infinite while with setting 10 minutes timeout (easily modifiable)
        $this->timeout = $this->loop->addTimer(((isset($this->vars['timeout']) AND is_int($this->vars['timeout'])) ? $this->vars['timeout'] : 600), function() use ($thisProcess) {

            echo _Parent\Core::say($thisProcess->vars['options']['__textPreprend'] . ' [ERROR] This children exceed the allowed timeout.', ['color' => 'red']);

            // Terminate process
            $thisProcess->process->terminate(SIGTERM);

            // Custom callback
            if(isset($this->onDatas['timeout'])) {
                $this->onDatas['timeout']($thisProcess);
            }

            return true;
        });

        // Set onExit callback
        $this->process->on('exit', function($exitCode, $termSignal) use ($thisProcess) {

            // Destroy values
            // Future: Detect type of exitCode to prevent removing crashed script
            echo _Parent\Core::say($thisProcess->vars['options']['__textPreprend'] . ' [INFO] Worker destroyed.', ['color' => 'brown']);

            // Cancel timeout
            if(!empty($thisProcess->timeout)) {
                $thisProcess->timeout->cancel();
            }

            // Custom user function
            if(isset($this->onDatas['exit'])) {
                $this->onDatas['exit']($thisProcess, $exitCode, $termSignal);
            }
            
            // Free memory
            $thisProcess->vars = NULL; // Remove all vars
            $thisProcess->onDatas = NULL; // Remove callbacks        
            $thisProcess->loop = NULL; // Remove the loop
            unset($thisProcess->process); // Remove the process
            unset($thisProcess);

            // Free memory by removing the class
            /*if(isset($this->vars['memory'])) {

                // Remove the class directly
                //$this->vars['memory']['sId'];
                var_dump($this->vars['memory']['map']);
            } else {

                // As we can't remove the class because no memory var has been set
                // The script is going to call __destruct and remove all $this->vars
                $thisProcess->__destruct();
            }*/
        });

        // Run everything
        $this->loop->addTimer(0.001, function($timer) use ($thisProcess) {

            $this->process->start($timer->getLoop());
            $this->process->stdout->on('data', function($output) use ($thisProcess) {

                // Output verifier
                $outputVerify = function($output) use ($thisProcess) {

                    // Check if the returned output is not empty
                    if(empty($output)) {
                        return false;   
                    }

                    // Decrypt & Decompress JSON
                    try {

                        $output = _Parent\Core::decode(_Parent\Core::$Cipher->decrypt($output));

                    } catch (\Exception $e) {

                        echo _Parent\Core::say($thisProcess->vars['options']['__textPreprend'] . ' [ERROR] Fatal error with this child.', ['color' => 'red']);
                        echo _Parent\Core::say($thisProcess->vars['options']['__textPreprend'] . ' [ERROR] Details:', ['color' => 'red']);
                        echo _Parent\Core::say($thisProcess->vars['options']['__textPreprend'] . ' [ERROR] ' . $output, ['color' => 'red']);

                        return false;
                    }

                    switch($output['type']) {

                        case 'gossip': // Say something
                        echo _Parent\Core::say($thisProcess->vars['options']['__textPreprend'] . ' ' . $output['childOutput']['text'], $output['childOutput']['options']);
                        break;

                        default:
                        if(isset($thisProcess->onDatas['response'])) {
                            $thisProcess->onDatas['response']($thisProcess, $output);
                        }
                        break;
                    }

                    return false;
                };

                // Trim output
                $output = trim($output);

                // Detect if here is more than one JSON string
                // This could create error if there is more than one so lets handle this
                if(strpos($output, CRLF)) {

                    foreach(explode(CRLF, $output) as $thisLine) {
                        $outputVerify($thisLine);
                    }

                    return true;
                }

                $outputVerify($output);
                return true;
            });
        });
    }
};