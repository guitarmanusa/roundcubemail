<?php

/**
 +-------------------------------------------------------------------------+
 | S/MIME driver for the Enigma Plugin                                     |
 |                                                                         |
 | Copyright (C) 2010-2015 The Roundcube Dev Team                          |
 |                                                                         |
 | Licensed under the GNU General Public License version 3 or              |
 | any later version with exceptions for skins & plugins.                  |
 | See the README file for a full license statement.                       |
 |                                                                         |
 +-------------------------------------------------------------------------+
 | Author: Aleksander Machniak <alec@alec.pl>                              |
 +-------------------------------------------------------------------------+
*/

class enigma_driver_phpssl extends enigma_driver
{
    private $rc;
    private $homedir;
    private $user;
    private $trusted_CAs;

    function __construct($user)
    {
        $rcmail = rcmail::get_instance();
        $this->rc   = $rcmail;
        $this->user = $user;
    }

    /**
     * Driver initialization and environment checking.
     * Should only return critical errors.
     *
     * @return mixed NULL on success, enigma_error on failure
     */
    function init()
    {
        $homedir = $this->rc->config->get('enigma_smime_homedir', INSTALL_PATH . '/plugins/enigma/home');
        $trusted_CAs = $this->rc->config->get('enigma_root_cas_location', "/etc/ssl/certs");
 
        if (!$homedir)
            return new enigma_error(enigma_error::INTERNAL,
                "Option 'enigma_smime_homedir' not specified");

        // check if homedir exists (create it if not) and is readable
        if (!file_exists($homedir))
            return new enigma_error(enigma_error::INTERNAL,
                "Certificate directory doesn't exists: $homedir");
        if (!is_writable($homedir))
            return new enigma_error(enigma_error::INTERNAL,
                "Certificate directory isn't writeable: $homedir");

        $homedir = $homedir . '/' . $this->user;

        // check if user's homedir exists (create it if not) and is readable
        if (!file_exists($homedir))
            mkdir($homedir, 0700);

        if (!file_exists($homedir))
            return new enigma_error(enigma_error::INTERNAL,
                "Unable to create certificate directory: $homedir");
        if (!is_writable($homedir))
            return new enigma_error(enigma_error::INTERNAL,
                "Unable to write to certificate directory: $homedir");

        $this->homedir = $homedir;
        
        //check if certchain.pem exists, if not create it
        if (!file_exists($homedir."/certchain.pem")) {
            touch($homedir."/certchain.pem");
            chmod($homedir."/certchain.pem",0600);
        }

    }

    function encrypt($text, $keys)
    {
    }

    function decrypt($text, $keys = array())
    {
    }

    function sign($text, $key, $passwd, $mode = null)
    {
    }

    /**
     * Signature verification.
     *
     * @param string Full MIME Message body (including headers)
     * @param string Signature, if message is of type S/MIME and body doesn't contain it
     *
     * @return mixed Signature information (enigma_signature) or enigma_error
     */
    function verify($text, $signature='')
    {
        // @TODO: use stored certificates
        // TODO: add user trusted CA's
        touch($this->homedir . "/smime.crt");

        $cert_file = $this->homedir . "/smime.crt";

        // try with certificate verification
        $sig      = openssl_pkcs7_verify($text, 0, $cert_file, array($trusted_CAs));
        $validity = true;

        if ($sig !== true) {
            // try without certificate verification
            $sig      = openssl_pkcs7_verify($msg_file, PKCS7_NOVERIFY, $cert_file);
            $validity = enigma_error::UNVERIFIED;
        }

        if ($sig === true) {
            $sig = $this->parse_sig_cert($cert_file, $validity);
        }
        else {
            $errorstr = $this->get_openssl_error();
            $sig = new enigma_error(enigma_error::INTERNAL, $errorstr);
        }

        // remove temp files
        @unlink($cert_file);

        return $sig;
    }

    public function import($content, $isfile=false, $password='')
    {
        $results = array();

        if ($isfile)
            $content = file_get_contents($content);
 
        $success = openssl_pkcs12_read($content, $results, $password);

        if ($success) {
            $success = openssl_pkey_export($results['pkey'], $result, '');
        } else {
            //TODO
        }
        /* from verify_sig_cert, see if it is applicable here
        if (empty($cert) || empty($cert['subject'])) {
            $errorstr = $this->get_openssl_error();
            return new enigma_error(enigma_error::INTERNAL, $errorstr);
        }

        $data = new enigma_signature();

        $data->id          = $cert['hash']; //?
        $data->valid       = $validity;
        $data->fingerprint = $cert['serialNumber'];
        $data->created     = $cert['validFrom_time_t'];
        $data->expires     = $cert['validTo_time_t'];
        $data->name        = $cert['subject']['CN'];
//        $data->comment     = '';
        $data->email       = $cert['subject']['emailAddress'];

        */
    }

    public function export($key)
    {
    }

    /**
     * Certificate listing.
     *
     * @param string Optional pattern for key ID, user ID or fingerprint
     *
     * @return mixed Array of enigma_key objects or enigma_error
     */
    public function list_keys($pattern='')
    {
        //Open file
        $certchain = file_get_contents($this->homedir."/certchain.pem", "r");

        if (!$certchain)
            //TODO return enigma error
            return false; 

        preg_match($certchain, $certs);
        $results = array();

        //For each in array(certs)
        foreach ( $certs as $cert ) {
            //openssl_x509_parse
            $cert_attribs = openssl_x509_parse($cert);
                //pull out identifiers, store to array
        }
        //return array
        return results;
    }

    public function get_key($keyid)
    {
    }

    public function gen_key($data)
    {
    }

    public function delete_key($keyid)
    {
    }

    public function delete_privkey($keyid)
    {
    }

    public function delete_pubkey($keyid)
    {
    }

    private function get_openssl_error()
    {
        $tmp = array();
        while ($errorstr = openssl_error_string()) {
            $tmp[] = $errorstr;
        }

        return join("\n", array_values($tmp));
    }

    private function ssl_errcode($output) {
        $results = array();

        if ($output !== true) {
            while ($errmsg = $this->get_openssl_error()) {
                if (preg_match('/^error:([^:]+):(.*)$/', $errmsg, $errcode)) {
                    switch ($errcode[1]) {
                        case '2107C080': 
                            $nocert = true;
                            break;
                        case '04091068':
                            $signerr = true;
                            break;
                        case '????????':   // It is necessary to clarify the error code when expired or incorrect certificate
                            $certbad = true;
                            break;
                        case '21075075':
                            $issbad = true;
                            break;
                        default:
                            $error = true;
                    }
                }
                else {
                    $error = true;
                }

                $results[] = $errmsg;
            }
            if ($error || $output === -1) {  
                $r = 'error';
            }
            elseif ($nocert) {
                $r = 'nocert';
            }
            elseif ($signerr) {
                $r = 'signerr';
            }
            elseif ($certbad) {
                $r = 'certbad';
            }
            elseif ($issbad) {
                $r = 'issbad';
            }
            else {
                $r = 'error';   // result is not true without error messages
            }
        }
        else {
            $r = 'ok';
        }
        return array($r,implode("\n",$results));
    }

    /**
     * Converts S/MIME Certificate object into Enigma's key object
     *
     * @param filename /path/to/certificate (PEM format)
     * @param validity boolean
     *
     * @return enigma_key Key object
     */
    private function parse_sig_cert($file, $validity)
    {
        $cert = openssl_x509_parse(file_get_contents($file));

        if (empty($cert) || empty($cert['subject'])) {
            $errorstr = $this->get_openssl_error();
            return new enigma_error(enigma_error::INTERNAL, $errorstr);
        }

        $data = new enigma_signature();

        $data->id          = $cert['hash']; //?
        $data->valid       = $validity;
        $data->fingerprint = $cert['serialNumber'];
        $data->created     = $cert['validFrom_time_t'];
        $data->expires     = $cert['validTo_time_t'];
        $data->name        = $cert['subject']['CN'];
//      $data->comment     = '';
        $data->email       = $cert['subject']['emailAddress'];

        return $data;
    }

    private function get_user_info_from_cert($file)
    {
        $cert     = openssl_x509_parse(file_get_contents($file));
        $sub      = $cert['subject'];   
        $ret      = array();

        if (array_key_exists('emailAddress', $sub)) {
            $ret['email'] = $sub['emailAddress'];
        }

        if (array_key_exists('CN', $sub)) {
            $ret['name'] = $sub['CN'];
        }

        if (array_key_exists('issuer', $cert)) {
            $issuer = $cert['issuer'];
            if (array_key_exists('O', $issuer)) {
                $ret['issuer'] = $issuer['O'];
            }
        }

        // Scan subAltName for email addresses
        if (array_key_exists('extensions', $cert) && array_key_exists('subjectAltName', $cert['extensions'])) {

            $emailAddresses = isset($ret['email'])?array($ret['email']):array();  

            // Not shure that it is correct, but do not drop address in Common Name if it is.            
            foreach (explode(', ', $cert['extensions']['subjectAltName']) as $altName) {
                $parts = explode(':', $altName);
                if ($parts[0] == 'email') {
                    array_push ($emailAddresses, $parts[1]);
                }
            }

            if (count($emailAddresses) > 0) {
                $ret['email'] = $emailAddresses;
            }
        }

        return $ret;
    }
}
