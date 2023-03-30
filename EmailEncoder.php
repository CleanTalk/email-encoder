<?php

namespace Cleantalk\Common\EmailEncoder;

use Cleantalk\Common\Antispam\Cleantalk;
use Cleantalk\Common\Antispam\CleantalkRequest;
use Cleantalk\Common\Helper\Helper;
use Cleantalk\Common\Variables\Post;

abstract class EmailEncoder
{
    const APBCT_AGENT = 'EmailEncoder-abstract';
    /**
     * @var string
     */
    private $api_key;

    /**
     * @var string
     */
    private $secret_key;

    /**
     * @var bool Show if the encryption functions are available in current surroundings
     */
    private $encryption_is_available;

    /**
     * Attribute names to skip content encoding contains them. Keep arrays of tag=>[attributes].
     * @var array[]
     */
    private $attribute_exclusions_signs = array(
        'input' => array('placeholder', 'value'),
    );

    /**
     * @var string[]
     */
    protected $decoded_emails_array;

    /**
     * @var string[]
     */
    protected $encoded_emails_array;

    /**
     * Temporary content to use in regexp callback
     * @var string
     */
    private $temp_content;

    /**
     * @var bool
     */
    protected $has_connection_error;

    /**
     * @var string
     */
    protected $comment;


    public function __construct($api_key)
    {
        $this->api_key = $api_key;
        $this->secret_key = md5($this->api_key);
        $this->encryption_is_available = function_exists('openssl_encrypt') && function_exists('openssl_decrypt');
        if ( ! $this->isExcludedRequest() ) {
            $this->init();
        }
    }

    abstract protected function init();

    /**
     * Main logic to hide emails.
     *
     * @param $content string
     *
     * @return string
     * @psalm-suppress PossiblyUnusedReturnValue
     */
    public function modifyContent($content)
    {
        if ( $this->isUserLoggedIn() ) {
            return $content;
        }

        if ( $this->hasContentExclusions($content) ) {
            return $content;
        }

        //will use this in regexp callback
        $this->temp_content = $content;

        return preg_replace_callback('/(mailto\:\b[_A-Za-z0-9-\.]+@[_A-Za-z0-9-\.]+\.[A-Za-z]{2,})|(\b[_A-Za-z0-9-\.]+@[_A-Za-z0-9-\.]+(\.[A-Za-z]{2,}))/', function ($matches) {

            if ( isset($matches[3]) && in_array(strtolower($matches[3]), ['.jpg', '.jpeg', '.png', '.gif', '.svg', '.webp']) ) {
                return $matches[0];
            }

            //chek if email is placed in excluded attributes and return unchanged if so
            if ( $this->hasAttributeExclusions($matches[0]) ) {
                return $matches[0];
            }

            if ( $this->isMailto($matches[0]) ) {
                return $this->encodeMailtoLink($matches[0]);
            }

            return $this->encodePlainEmail($matches[0]);
        }, $content);
    }

    /**
     * Ajax handler for the apbct_decode_email action
     *
     * @return void returns json string to the JS
     */
    public function ajaxDecodeEmailHandler()
    {
        $this->checkReferer();

        $decoded_emails_array = $this->decodeEmailFromPost();
        if ( $this->checkRequest() ) {
            //has error response from cloud
            if ( $this->has_connection_error ) {
                $response = [
                    'success' => false,
                    'data'    => $this->compileResponse($decoded_emails_array, false)
                ];
            } else {
                //decoding is allowed by cloud
                $response = [
                    'success' => true,
                    'data'    => $this->compileResponse($decoded_emails_array, true)
                ];
            }

        } else {
            //decoding is not allowed by cloud
            $response = [
                'success' => false,
                'data'    => $this->compileResponse($decoded_emails_array, false)
            ];
        }
        exit(json_encode($response, JSON_FORCE_OBJECT));
    }

    /**
     * Checking nonce logic here need to be implemented.
     *
     * @return bool
     */
    abstract protected function checkReferer();

    /**
     * Main logic of the decoding the encoded data.
     *
     * @return string[] array of decoded email
     */
    public function decodeEmailFromPost()
    {
        $encoded_emails_array = Post::get('encodedEmails');
        $encoded_emails_array = str_replace('\\', '', $encoded_emails_array);
        $this->encoded_emails_array = json_decode($encoded_emails_array, true);

        foreach ( $this->encoded_emails_array as $_key => $encoded_email) {
            $this->decoded_emails_array[$encoded_email] = $this->decodeString($encoded_email, $this->secret_key);
        }

        return $this->decoded_emails_array;
    }

    /**
     * Ajax handler for the apbct_decode_email action
     *
     * @return bool returns json string to the JS
     */
    protected function checkRequest()
    {
        $browser_sign          = hash('sha256', Post::get('browser_signature_params'));
        $event_javascript_data = Helper::isJson(Post::get('event_javascript_data'))
            ? Post::get('event_javascript_data')
            : stripslashes(Post::get('event_javascript_data'));

        $params = array(
            'auth_key'              => $this->api_key,        // Access key
            'agent'                 => static::APBCT_AGENT,
            'event_token'           => null,                   // Unique event ID
            'event_javascript_data' => $event_javascript_data, // JSON-string params to analysis
            'browser_sign'          => $browser_sign,          // Browser ID
            'sender_ip'             => Helper::ipGet(),        // IP address
            'event_type'            => 'CONTACT_DECODING',     // 'GENERAL_BOT_CHECK' || 'CONTACT_DECODING'
            'message_to_log'        => json_encode(array_values($this->decoded_emails_array), JSON_FORCE_OBJECT),   // Custom message
            'page_url'              => Post::get('post_url'),
            'sender_info'           => array(
                'site_referrer'         => Post::get('referrer'),
            ),
        );

        $ct_request = new CleantalkRequest($params);

        $ct = new Cleantalk();
        $this->has_connection_error = false;
        $ct->server_url     = 'https://moderate.cleantalk.org';
        $api_response = $ct->checkBot($ct_request);

        // Allow to see to the decoded contact if error occurred
        // Send error as comment in this case
        if ( ! empty($api_response->errstr)) {
            $this->comment = $api_response->errstr;
            $this->has_connection_error = true;
            return true;
        }

        $stub_comment = $api_response->allow
            ? $this->translate('Allowed')
            : $this->translate('Blocked');

        $this->comment = ! empty($api_response->comment) ? $api_response->comment : $stub_comment;

        return $api_response->allow === 1;
    }

    private function compileResponse($decoded_emails_array, $is_allowed)
    {
        $result = array();
        foreach ( $decoded_emails_array as $encoded_email => $decoded_email ) {
            $result[] = array(
                'is_allowed' => $is_allowed,
                'show_comment' => !$is_allowed,
                'comment' => $this->comment,
                'encoded_email' => strip_tags($encoded_email, '<a>'),
                'decoded_email' => $is_allowed ? strip_tags($decoded_email, '<a>') : '',
            );
        }
        return $result;
    }

    /**
     * Encoding any string
     *
     * @param $plain_string string
     * @param $key string
     *
     * @return string
     */
    private function encodeString($plain_string, $key)
    {
        if ( $this->encryption_is_available ) {
            $encoded_email = htmlspecialchars(@openssl_encrypt($plain_string, 'aes-128-cbc', $key));
        } else {
            $encoded_email = htmlspecialchars(base64_encode(str_rot13($plain_string)));
        }
        return $encoded_email;
    }

    /**
     * Decoding previously encoded string
     *
     * @param $encoded_string string
     * @param $key string
     *
     * @return string
     */
    private function decodeString($encoded_string, $key)
    {
        if ( $this->encryption_is_available  ) {
            $decoded_email = htmlspecialchars_decode(@openssl_decrypt($encoded_string, 'aes-128-cbc', $key));
        } else {
            $decoded_email = htmlspecialchars_decode(base64_decode($encoded_string));
            $decoded_email = str_rot13($decoded_email);
        }
        return $decoded_email;
    }

    /**
     * Obfuscate an email to the s****@**.com view
     *
     * @param $email string
     *
     * @return string
     */
    private function obfuscateEmail($email)
    {
        $first_part = strpos($email, '@') > 2
            ? substr($email, 0, 2) . str_pad('', strpos($email, '@') - 2, '*')
            : str_pad('', strpos($email, '@'), '*');
        $second_part = substr($email, strpos($email, '@') + 1, 2)
                       . str_pad('', strpos($email, '.', strpos($email, '@')) - 3 - strpos($email, '@'), '*');
        $last_part = substr($email, (int) strrpos($email, '.', -1) - strlen($email));
        return $first_part . '@' . $second_part . $last_part;
    }

    /**
     * Method to process plain email
     *
     * @param $email_str string
     *
     * @return string
     */
    private function encodePlainEmail($email_str)
    {
        $obfuscated = $this->obfuscateEmail($email_str);

        $encoded = $this->encodeString($email_str, $this->secret_key);

        return '<span 
                data-original-string="' . $encoded . '"
                class="apbct-email-encoder"
                title="' . htmlspecialchars($this->getTooltip()) . '">' . $obfuscated . '</span>';
    }

    /**
     * Checking if the string contains mailto: link
     *
     * @param $string string
     *
     * @return bool
     */
    private function isMailto($string)
    {
        return strpos($string, 'mailto:') !== false;
    }

    /**
     * Method to process mailto: links
     *
     * @param $mailto_link_str string
     *
     * @return string
     */
    private function encodeMailtoLink($mailto_link_str)
    {
        // Get inner tag text and place it in $matches[1]
        preg_match('/mailto\:(\b[_A-Za-z0-9-\.]+@[_A-Za-z0-9-\.]+\.[A-Za-z]{2,})/', $mailto_link_str, $matches);
        if ( isset($matches[1]) ) {
            $mailto_inner_text = preg_replace_callback('/\b[_A-Za-z0-9-\.]+@[_A-Za-z0-9-\.]+\.[A-Za-z]{2,}/', function ($matches) {
                return $this->obfuscateEmail($matches[0]);
            }, $matches[1]);
        }
        $mailto_link_str = str_replace('mailto:', '', $mailto_link_str);
        $encoded = $this->encodeString($mailto_link_str, $this->secret_key);

        $text = isset($mailto_inner_text) ? $mailto_inner_text : $mailto_link_str;

        return 'mailto:' . $text . '" data-original-string="' . $encoded . '" title="' . htmlspecialchars($this->getTooltip());
    }

    /**
     * Get text for the title attribute
     *
     * @return string
     */
    private function getTooltip()
    {
        return $this->translate('This contact has been encoded by CleanTalk. Click to decode. To finish the decoding make sure that JavaScript is enabled in your browser.');
    }

    /**
     * Check content if it contains exclusions from exclusion list
     * @param $content - content to check
     * @return bool - true if exclusions found, else - false
     */
    private function hasContentExclusions($content)
    {
        $content_exclusions_signs = $this->getContentExclusionsSigns();
        if ( ! empty($content_exclusions_signs) && is_array($content_exclusions_signs) ) {
            foreach ( array_values($content_exclusions_signs) as $_signs_array => $signs ) {
                //process each of sub-arrays of signs
                $signs_found_count = 0;
                if ( isset($signs) && is_array($signs) ) {
                    //chek all the signs in the sub-array
                    foreach ( $signs as $sign ) {
                        if ( is_string($sign) ) {
                            if ( strpos($content, $sign) === false ) {
                                continue;
                            } else {
                                $signs_found_count++;
                            }
                        }
                    }
                    //if each of signs in the sub-array are found return true
                    if ( $signs_found_count === count($signs) ) {
                        return true;
                    }
                }
            }
        }
        //no signs found
        return false;
    }

    /**
     * @return array
     */
    abstract protected function getContentExclusionsSigns();

    /**
     * Excluded requests
     */
    abstract protected function isExcludedRequest();

    /**
     * Check if email is placed in the tag that has attributes of exclusions.
     *
     * @param $email_match - email
     * @return bool
     */
    private function hasAttributeExclusions($email_match)
    {
        foreach ( $this->attribute_exclusions_signs as $tag => $array_of_attributes ) {
            foreach ( $array_of_attributes as $attribute ) {
                $pattern = '/<' . $tag . '.*' . $attribute . '="' . $email_match . '"/';
                preg_match($pattern, $this->temp_content, $attr_match);
                if ( !empty($attr_match) ) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Contains translation logic.
     * Overload this method in the CMS-based class if it will be necessary.
     *
     * @param $string
     * @return string
     */
    protected function translate($string)
    {
        return $string;
    }

    /**
     * Implement here checking if the current user has logged in.
     *
     * @return bool
     */
    abstract protected function isUserLoggedIn();
}
