<?php use App\Http\Middleware\EncryptMiddleware;

if (!defined('BASEPATH')) exit('No direct script access allowed');

class Cp_payout
{

    public function status($reqData)
    {
        $request = array(
            "method" => "POST",
            "url" => "pay/check-status",
            "parameter" => $reqData
        );
        $response = $this->hit($request);
        return $response;
    }

    public function balance()
    {
        $request = array(
            "method" => "POST",
            "url" => "pay/balance-enquiry",
            "parameter" => ""
        );
        $response = $this->finalResponse($this->hit($request));
        return $response;
    }

    public function singlepayout($reqData)
    {
        $request = array(
            "method" => "POST",
            "url" => "pay/singlepayout",
            "parameter" => $reqData
        );
        $response = $this->hit($request);
        return $response;
    }



    public function __construct()
    {
        $this->mainurl = "https://uatapi.cipherpay.in/api/v2/";
        $this->key = "";         // token
        $this->partnerid = "";         // 2022XXXX
        $this->headerJson = '{"partnerId": "", "headerToken": ""}';     //header json
        $this->publicKey = "";     //body key
        $this->aesKey = '';
        $this->aesIv = '';
        $this->publicKeyHeader = '';       //header key

        $this->partnerToken = ''; //partner Token
    }

    /**
     * Function to hit the API
     *
     * @param $reqData [method, url, parameter]
     * @return array|mixed
     * @author Himanshu himanshu.chawla@ciphersquare.tech
     */
    private function hit($reqData)
    {
        $url = $this->mainurl . $reqData['url'];
        $num = time();
        $reqData['jwt'] = $this->getjwttoken();
        $this->writelog("REQUEST" . $num, $reqData);
        if (!empty($reqData['parameter'])) {
            $parameter = json_encode($reqData['parameter']);
        } else {
            $parameter = "";
        }
        $info = $this->finalRequest($parameter);
        $curl = curl_init();
        curl_setopt_array($curl, array(
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_ENCODING => "",
            CURLOPT_MAXREDIRS => 10,
            CURLOPT_TIMEOUT => 30,
            CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
            CURLOPT_CUSTOMREQUEST => $reqData['method'],
            CURLOPT_POSTFIELDS => json_encode($info['payload']),
            CURLOPT_HTTPHEADER => array(
                "Token: " . $reqData['jwt'],
                "Auth: " . $info['Auth'],
                "Key:" . $info['Key'],
                "cache-control: no-cache",
                "content-type: application/json",
                "User-Agent: PostmanRuntime/7.29.2"
            ),
        ));
        $response = curl_exec($curl);
        // echo $response;
        if (curl_errno($curl)) {
            $resp = array("errorCode" => "PAYSPRINT-001", "error_code" => curl_errno($curl), "message" => curl_error($curl), "errorMessage" => "Unable to get response please try again later");
        } else {
            $resp = $this->response($response);
        }
        $this->writelog("RESPONSE" . $num, $resp);
        return $resp;
    }


    /**
     *  Returns encoded JWT token
     *
     * @return string
     * @author Himanshu himanshu.chawla@ciphersquare.tech
     */
    private function getjwttoken()
    {
        $reqId = rand(111111, 999999);
        $tokendata = array(
            "timestamp" => date('Y-m-d H:i:s'),
            "partnerId" => $this->partnerid,
            "reqId" => $reqId,
        );
        $header = $header = array(
            'alg' => 'HS256',
            'typ' => 'JWT'
        );

        $secret = $this->partnerToken;

        return $this->generateJwt($header, $tokendata, $secret);
    }


    /**
     * Function to encode JWT token
     *
     * @param $header [alg, typ]
     * @param $payload [timestamp, partnerId, reqId]
     * @param $secret string
     * @return string
     * @author Himanshu himanshu.chawla@ciphersquare.tech
     */
    function generateJwt($header, $payload, $secret)
    {
        $headerEncoded = $this->base64UrlEncode(json_encode($header));
        $payloadEncoded = $this->base64UrlEncode(json_encode($payload));
        $signature = hash_hmac('sha256', $headerEncoded . '.' . $payloadEncoded, $secret, true);
        $signatureEncoded = $this->base64UrlEncode($signature);
        return $headerEncoded . '.' . $payloadEncoded . '.' . $signatureEncoded;
    }

    /**
     * base 64 url encode
     *
     * @param $data
     * @return string
     */
    function base64UrlEncode($data)
    {
        $urlSafeData = strtr(base64_encode($data), '+/', '-_');
        return rtrim($urlSafeData, '=');
    }

    /**
     * Function to writeLogs,
     * Need to be implemented by the user
     * Called from hit function before and after the API call
     *
     * @param $type
     * @param $req
     * @return void
     */
    private function writelog($type, $req)
    {
        //write your code here
    }

    /**
     * Function to create final request for the API
     *
     *
     * @param $parameters
     * @return array [Auth, Key, payload]
     * @author Himanshu himanshu.chawla@ciphersquare.tech
     */
    private function finalRequest($parameters = "")
    {
        $salt = bin2hex(openssl_random_pseudo_bytes(8));

        $data = $this->generateAesKey($salt);
        $key = $data[0];
        $iv = $data[1];
        $cipher = 'aes-128-cbc';

        if ($parameters != "") {
            $encrypted = openssl_encrypt(json_encode($parameters), $cipher, $key, OPENSSL_RAW_DATA, $iv);
            $encrypted = base64_encode($encrypted);
        }


        $encryptedSalt = $this->rsaEncrypt($salt, $this->publicKey);

        $encryptedHeader = $this->rsaEncrypt($this->headerJson, $this->publicKeyHeader);

        $request = [
            'Auth' => $encryptedHeader,
            'Key' => $encryptedSalt,
            'payload' => $parameters ? ['requestData' => $encrypted] : null,
        ];

        return $request;
    }

    /**
     * Function to generate AES key, using salt,
     * salt will be used as IV
     *
     * @param $salt
     * @return array [key, iv]
     * @author Himanshu himanshu.chawla@ciphersquare.tech
     */
    private function generateAesKey($salt)
    {
        $salt = hex2bin($salt);
        $passphrase = 'CipherPay API Payout';
        $iterationCount = 10000;
        $keySize = 128;
        $hashAlgorithm = 'sha1';
        $key = openssl_pbkdf2($passphrase, $salt, $keySize / 8, $iterationCount, $hashAlgorithm);
        $this->aesKey = $key;
        $this->aesIv = bin2hex($salt);
        return [$key, bin2hex($salt)];
    }

    /**
     * Function to encrypt data using RSA
     *
     * @param $data
     * @param $publicKey
     * @return string encrypted string
     * @author Himanshu himanshu.chawla@ciphersquare.tech
     *
     */
    private function rsaEncrypt($data, $publicKey)
    {
        $publicKey = openssl_get_publickey($publicKey);
        openssl_public_encrypt($data, $encrypted, $publicKey);
        return base64_encode($encrypted);
    }

    /**
     * @param $response
     * @return mixed
     */
    function response($response)
    {
        $res = json_decode($response, TRUE);
        return $res;
    }



    /**
     * Function to decrypt the response
     *
     *
     * @param $response
     * @return mixed
     * @author Himanshu himanshu.chawla@ciphersquare.tech
     */
    private function finalResponse($response)
    {
        $responseData = $response['returnData'];
        $encrypted = base64_decode($responseData);
        $decrypted = openssl_decrypt($encrypted, 'aes-128-cbc', $this->aesKey, OPENSSL_RAW_DATA, $this->aesIv);
        $decrypted = json_decode($decrypted, true);
        return $decrypted;
    }


    /**
     * @param $headerKey string base64 encoded received from header
     * @param $requestData string base64 encoded received from body
     * @param $privateKey string private key of the merchant
     * @return false|string
     */
    public function consumeCallback($headerKey, $requestData, $privateKey) {
        $key = base64_decode($headerKey);
        $requestData = base64_decode($requestData);
        $privateKey = openssl_pkey_get_private($privateKey);
        openssl_private_decrypt($key, $salt, $privateKey);
        $aesKey = $this->generateAesKey($salt)[0];
        $output = openssl_decrypt($requestData, 'AES-128-CBC', $aesKey, OPENSSL_RAW_DATA, $salt);
        return $output;
    }


}

?>