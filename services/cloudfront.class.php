<?php
/**
 * File: CloudFront
 * 	Amazon CloudFront CDN Service (http://aws.amazon.com/cloudfront)
 *
 * Version:
 * 	2010.03.26
 *
 * Copyright:
 * 	2006-2010 Ryan Parman, Foleeo, Inc., and contributors.
 *
 * License:
 * 	Simplified BSD License - http://opensource.org/licenses/bsd-license.php
 *
 * See Also:
 * 	CloudFusion - http://getcloudfusion.com
 * 	Amazon CloudFront - http://aws.amazon.com/cloudfront
 */


/*%******************************************************************************************%*/
// CONSTANTS

/**
 * Constant: CDN_DEFAULT_URL
 * 	Specify the default queue URL.
 */
define('CDN_DEFAULT_URL', 'cloudfront.amazonaws.com');


/*%******************************************************************************************%*/
// EXCEPTIONS

/**
 * Exception: CloudFront_Exception
 * 	Default CloudFront Exception.
 */
class CloudFront_Exception extends Exception {}


/*%******************************************************************************************%*/
// MAIN CLASS

/**
 * Class: AmazonCloudFront
 * 	Container for all Amazon CloudFront-related methods. Inherits additional methods from CloudFusion.
 *
 * Extends:
 * 	CloudFusion
 */
class AmazonCloudFront extends CloudFusion
{
	/**
	 * Property: base_standard_xml
	 * 	The base content to use for generating the DistributionConfig XML.
	 */
	var $base_xml;

	/**
	 * Property: domain
	 * 	The CloudFront distribution domain to use.
	 */
	var $domain;

	/**
	 * Property: key_pair_id
	 * 	The RSA key pair ID to use.
	 */
	var $key_pair_id;

	/**
	 * Property: private_key
	 * 	The RSA private key resource locator.
	 */
	var $private_key;


	/*%******************************************************************************************%*/
	// CONSTRUCTOR

	/**
	 * Method: __construct()
	 * 	The constructor
	 *
	 * Access:
	 * 	public
	 *
	 * Parameters:
	 * 	key - _string_ (Optional) Your Amazon API Key. If blank, it will look for the <AWS_KEY> constant.
	 * 	secret_key - _string_ (Optional) Your Amazon API Secret Key. If blank, it will look for the <AWS_SECRET_KEY> constant.
	 *
	 * Returns:
	 * 	_boolean_ false if no valid values are set, otherwise true.
	 */
	public function __construct($key = null, $secret_key = null)
	{
		$this->api_version = '2009-12-01';
		$this->hostname = CDN_DEFAULT_URL;

		$this->base_xml = '<?xml version="1.0" encoding="UTF-8"?><%s xmlns="http://cloudfront.amazonaws.com/doc/' . $this->api_version . '/"></%1$s>';

		if (!$key && !defined('AWS_KEY'))
		{
			throw new CloudFront_Exception('No account key was passed into the constructor, nor was it set in the AWS_KEY constant.');
		}

		if (!$secret_key && !defined('AWS_SECRET_KEY'))
		{
			throw new CloudFront_Exception('No account secret was passed into the constructor, nor was it set in the AWS_SECRET_KEY constant.');
		}

		return parent::__construct($key, $secret_key);
	}


	/*%******************************************************************************************%*/
	// AUTHENTICATION

	/**
	 * Method: authenticate()
	 * 	Authenticates a connection to CloudFront. This should not be used directly unless you're writing custom methods for this class.
	 *
	 * Access:
	 * 	public
 	 *
	 * Parameters:
	 * 	method - _string_ (Required) The HTTP method to use to connect. Accepts <HTTP_GET>, <HTTP_POST>, <HTTP_PUT>, <HTTP_DELETE>, and <HTTP_HEAD>.
	 * 	path - _string_ (Optional) The endpoint path to make requests to.
	 * 	opt - _array_ (Optional) Associative array of parameters for authenticating. See the individual methods for allowed keys.
	 * 	xml - _string_ (Optional) The XML body content to send along in the request.
	 * 	etag - _string_ (Optional) The ETag value to pass along with the If-Match HTTP header.
	 *
	 * Returns:
	 * 	<ResponseCore> object
 	 *
	 * See Also:
	 * 	http://docs.amazonwebservices.com/AmazonCloudFront/latest/DeveloperGuide/RESTAuthentication.html
	 */
	public function authenticate($method = HTTP_GET, $path = null, $opt = null, $xml = null, $etag = null)
	{
		$querystring = null;

		if (!$opt)
		{
			$opt = array();
		}
		else
		{
			// Generating a pre-signed URL
			if (isset($opt['conditions']))
			{
				// Put this at the top since if we're requesting a URL be generated the rest of this function is not going to be executed
				$domain = null;
				$filename = null;
				$conditions = null;
				$private_key = null;
				$return = array();
				extract($opt);

				if (isset($conditions['DateLessThanExact']))
				{
					$expires = $conditions['DateLessThanExact'];
					unset($conditions['DateLessThanExact']);
				}
				else
				{
					// Get the expiry time
					$expires = time() + $conditions['DateLessThan'];
				}

				// Reformat the conditions
				$conditions['DateLessThan'] = array(
					'AWS:EpochTime' => $expires
				);

				if (isset($conditions['DateGreaterThan']))
				{
					$conditions['DateGreaterThan'] = array(
						'AWS:EpochTime' => time() + $conditions['DateGreaterThan']
					);
				}
				elseif (isset($conditions['DateGreaterThanExact']))
				{
					$conditions['DateGreaterThan'] = array(
						'AWS:EpochTime' => $conditions['DateGreaterThanExact']
					);

					unset($conditions['DateGreaterThanExact']);
				}

				if (isset($conditions['IpAddress']))
				{
					$conditions['IpAddress'] = array(
						'AWS:SourceIp' => $conditions['IpAddress']
					);
				}

				// Prepare the resource
				$resource = 'http://' . $domain . '/' . str_replace(' ', '%20', $filename);

				// Canned policy
				if (count($conditions) === 1)
				{
					// Prepare the policy - the str_replace is because json_encode has a bug where it escapes forward slashes
					$policy = $this->util->json_encode(array(
						'Statement' => array(
							array(
								'Resource' => $resource,
								'Condition' => $conditions
							)
						)
					));

					$return['expires'] = $expires;
				}
				else
				{
					// Prepare the policy
					// The str_replace is because json_encode has a bug where it escapes forward slashes -- the new line is required for custom policies
					$policy = $this->util->json_encode(array(
						'Statement' => array(
							array(
								'Resource' => $resource,
								'Condition' => $conditions
							)
						)
					)) . "\n";

					// URL-safe the policy
					$policy_encoded = strtr(base64_encode($policy), '+=/', '-_~');
					$return['policy'] = $policy_encoded;
				}

				// Sign the policy
				openssl_sign($policy, $signature, $private_key);

				// URL-safe the signature
				$signature = strtr(base64_encode($signature), '+=/', '-_~');

				$return['resource'] = $resource;
				$return['signature'] = $signature;

				return $return;
			}

			// Generate the querystring from $opt, removing a reference to returnCurlHandle.
			$query = $opt;

			// Get the action from $opt
			if (isset($query['action']))
			{
				unset($query['action']);
			}

			if (isset($query['returnCurlHandle']))
			{
				unset($query['returnCurlHandle']);
			}

			if (count($query) > 0)
			{
				$querystring = '?' . $this->util->to_query_string($query);
			}
		}

		// Gather information to pass along to other classes.
		$helpers = array(
			'utilities' => $this->utilities_class,
			'request' => $this->request_class,
			'response' => $this->response_class,
		);

		// Compose the request.
		$request_url = 'https://' . $this->hostname . '/' . $this->api_version . '/' . $opt['action'];

		$request_url .= ($path) ? $path : '';
		$request_url .= ($querystring) ? $querystring : '';
		$request = new $this->request_class($request_url, $this->set_proxy, $helpers);

		// Generate required headers.
		$request->set_method($method);
		$canonical_date = gmdate(DATE_FORMAT_RFC2616);
		$request->add_header('x-amz-date', $canonical_date);
		$signature = $this->util->hex_to_base64(hash_hmac('sha1', $canonical_date, $this->secret_key));
		$request->add_header('Authorization', 'AWS ' . $this->key . ':' . $signature);

		// Add configuration XML if we have it.
		if ($xml)
		{
			$request->add_header('Content-Length', strlen($xml));
			$request->add_header('Content-Type', 'text/plain');
			$request->set_body($xml);
		}

		// Set If-Match: ETag header if we have one.
		if ($etag)
		{
			$request->add_header('If-Match', $etag);
		}

		// If we have a "true" value for returnCurlHandle, do that instead of completing the request.
		if (isset($opt['returnCurlHandle']))
		{
			return $request->prep_request();
		}

		// Send!
		$request->send_request();

		// Prepare the response.
		$headers = $request->get_response_header();
		$headers['x-cloudfusion-requesturl'] = $request_url;
		if ($xml) $headers['x-cloudfusion-body'] = $xml;
		$data = new $this->response_class($headers, new SimpleXMLElement($request->get_response_body()), $request->get_response_code());

		// Return!
		return $data;
	}

	/**
	 * Method: set_domain()
	 * 	Set the domain to be used for your CloudFront distribution.
	 *
	 * Access:
	 * 	public
 	 *
	 * Parameters:
	 * 	domain - _string_ (Required) The hostname to use.
	 *
	 * Returns:
	 * 	void
 	 *
	 */
	public function set_domain($domain)
	{
		$this->domain = $domain;
	}

	/**
	 * Method: set_keypair_id()
	 * 	Set the key ID of the RSA key pair being used.
	 *
	 * Access:
	 * 	public
 	 *
	 * Parameters:
	 * 	key_pair_id - _string_ (Required) ID of the RSA key pair being used.
	 *
	 * Returns:
	 * 	void
 	 *
	 */
	public function set_keypair_id($key_pair_id)
	{
		$this->key_pair_id = $key_pair_id;
	}

	/**
	 * Method: set_private_key()
	 * 	Set the private key resource locator being used.
	 *
	 * Access:
	 * 	public
 	 *
	 * Parameters:
	 *	private_key - _string_ (Optional) RSA private key resource identifier used to sign requests. You must use openssl_get_privatekey() or openssl_pkey_get_private() to get the resource identifier. Don't forget to call openssl_free_key() when you're done.
	 *
	 * Returns:
	 * 	void
 	 *
	 */
	public function set_private_key($private_key)
	{
		$this->private_key = $private_key;
	}


	/*%******************************************************************************************%*/
	// SET CUSTOM SETTINGS

	/**
	 * Method: disable_ssl()
	 * 	Throws an error because SSL is required for the CloudFront service.
	 *
	 * Access:
	 * 	public
	 *
	 * Returns:
	 * 	void
	 */
	public function disable_ssl()
	{
		throw new CloudFront_Exception('SSL/HTTPS is REQUIRED for CloudFront and cannot be disabled.');
	}


	/*%******************************************************************************************%*/
	// GENERATE DISTRIBUTION CONFIG XML

	/**
	 * Method: generate_config_xml()
	 * 	Used to generate the Distribution Config XML used in <create_distribution()> and <set_distribution_config()>.
	 *
	 * Access:
	 * 	public
 	 *
	 * Parameters:
	 * 	origin - _string_ (Required) The source S3 bucket to use for the CloudFront distribution.
	 * 	caller_reference - _string_ (Required) A unique identifier for the request. Must be generated on your own. A time stamp or hash is a good example.
 	 * 	opt - _array_ (Optional) Associative array of parameters which can have the following keys:
 	 *
 	 * Keys for the $opt parameter:
	 * 	CNAME - _string_|_array_ (Optional) A DNS CNAME to use to map to the CloudFront distribution. If setting more than one, use an indexed array. Supports 1-10 CNAMEs.
	 * 	Comment - _integer_ (Optional) A comment to apply to the distribution. Cannot exceed 128 characters.
	 *	OriginAccessIdentity - _string_ (Optional) The Origin Access Identity associated with this distribution. Use the Identity ID, not the CanonicalId.
	 *	TrustedSigners - _array_ (Optional) Array of AWS Account numbers who are trusted signers. You must explicitly add "Self" (exactly as shown) to the array if you want your own account to be a trusted signer.
	 * 	Enabled - _string_ (Optional) Defaults to true. Use this to set Enabled to false.
	 * 	Streaming - _boolean_ (Optional) Whether this should be for a streaming distribution or not. Defaults to false.
	 *
	 * Returns:
	 * 	String DistributionConfig XML document.
	 *
	 * Examples:
	 * 	example::cloudfront/generate_config_xml3.phpt:
	 * 	example::cloudfront/generate_config_xml4.phpt:
	 * 	example::cloudfront/generate_config_xml5.phpt:
	 * 	example::cloudfront/generate_config_xml9.phpt:
	 * 	example::cloudfront/generate_config_xml10.phpt:
 	 *
	 * See Also:
	 * 	Related - <generate_config_xml()>, <update_config_xml()>, <remove_cname()>
	 */
	public function generate_config_xml($origin, $caller_reference, $opt = null)
	{
		// Default, empty XML
		if (isset($opt['Streaming']) && $opt['Streaming'] == (bool) true) // Did we ask to stream?
		{
			$xml = simplexml_load_string(sprintf($this->base_xml,'StreamingDistributionConfig'));
		}
		else
		{
			$xml = simplexml_load_string(sprintf($this->base_xml,'DistributionConfig'));
		}

		// Origin
		if (stripos($origin, '.s3.amazonaws.com') !== false)
		{
			$xml->addChild('Origin', $origin);
		}
		else
		{
			$xml->addChild('Origin', $origin . '.s3.amazonaws.com');
		}

		// CallerReference
		$xml->addChild('CallerReference', $caller_reference);

		// CNAME
		if (isset($opt['CNAME']))
		{
			if (is_array($opt['CNAME']))
			{
				foreach ($opt['CNAME'] as $cname)
				{
					$xml->addChild('CNAME', $cname);
				}
			}
			else
			{
				$xml->addChild('CNAME', $opt['CNAME']);
			}
		}

		// Comment
		if (isset($opt['Comment']))
		{
			$xml->addChild('Comment', $opt['Comment']);
		}

		// Enabled
		if (isset($opt['Enabled']))
		{
			$xml->addChild('Enabled', $opt['Enabled'] ? 'true' : 'false');
		}
		else
		{
			$xml->addChild('Enabled', 'true');
		}

		// Logging
		if (isset($opt['Logging']))
		{
			if (is_array($opt['Logging']))
			{
				$logging = $xml->addChild('Logging');
				$bucket_name = $opt['Logging']['Bucket'];

				// Origin
				if (stripos($bucket_name, '.s3.amazonaws.com') !== false)
				{
					$logging->addChild('Bucket', $bucket_name);
				}
				else
				{
					$logging->addChild('Bucket', $bucket_name . '.s3.amazonaws.com');
				}

				$logging->addChild('Prefix', $opt['Logging']['Prefix']);
			}
		}

		// Origin Access Identity
		if (isset($opt['OriginAccessIdentity']))
		{
			$xml->addChild('OriginAccessIdentity', 'origin-access-identity/cloudfront/' . $opt['OriginAccessIdentity']);
		}

		// Trusted Signers
		if (isset($opt['TrustedSigners']))
		{
			if (is_array($opt['TrustedSigners']))
			{
				$trusted_signers = $xml->addChild('TrustedSigners');
				foreach($opt['TrustedSigners'] as $signer)
				{
					if ($signer === 'Self')
					{
						$trusted_signers->addChild('Self');
					}
					else
					{
						$trusted_signers->addChild('AwsAccountNumber', $signer);
					}
				}
			}
		}

		return $xml->asXML();
	}

	/**
	 * Method: update_config_xml()
	 * 	Used to update an existing DistributionConfig XML document.
	 *
	 * Access:
	 * 	public
 	 *
	 * Parameters:
	 * 	xml - _SimpleXMLElement_|_ResponseCore_|_string_ (Required) The source DistributionConfig XML to make updates to. Can be the SimpleXMLElement body of a <get_distribution_config()> response, the entire <ResponseCore> of a <get_distribution_config()> response, or a string of XML generated by <generate_config_xml()> or <update_config_xml()>.
 	 * 	opt - _array_ (Optional) Associative array of parameters which can have the following keys:
 	 *
 	 * Keys for the $opt parameter:
	 * 	CNAME - _string_|_array_ (Optional) This (these) value(s) will be ADDED to the existing list of CNAME values. To remove a CNAME value, see <remove_cname()>.
	 * 	Comment - _integer_ (Optional) This value will replace the existing value for 'Comment'. Cannot exceed 128 characters.
	 * 	Enabled - _string_ (Optional) This value will replace the existing value for 'Enabled'.
	 *	Logging - _array_ (Optional)
	 *	OriginAccessIdentity - _string_ (Optional) This value will replace the existing value for 'OriginAccessIdentity'.
	 *	TrustedSigners - _array_ (Optional) This array will replace the existing array for 'TrustedSigners'.
	 * 	Streaming - _boolean_ (Optional) Whether this should be for a streaming distribution or not. Defaults to false.
	 *
	 * Returns:
	 * 	String DistributionConfig XML document.
	 *
	 * Examples:
	 * 	example::cloudfront/update_config_xml4.phpt:
	 * 	example::cloudfront/update_config_xml10.phpt:
	 *
	 * See Also:
	 * 	Related - <generate_config_xml()>, <update_config_xml()>, <remove_cname()>
	 */
	public function update_config_xml($xml, $opt = null)
	{
		// If we receive a full ResponseCore object, only use the body.
		if ($xml instanceof ResponseCore)
		{
			$xml = $xml->body;
		}

		// If we received a string of XML, convert it into a SimpleXMLElement object.
		if (is_string($xml))
		{
			$xml = simplexml_load_string($xml);
		}

		// Default, empty XML
		if (isset($opt['Streaming']) && $opt['Streaming'] == (bool) true) // Did we ask to stream?
		{
			$update = simplexml_load_string(sprintf($this->base_xml, 'StreamingDistributionConfig'));
		}
		else
		{
			$update = simplexml_load_string(sprintf($this->base_xml, 'DistributionConfig'));
		}

		// These can't change.
		$update->addChild('Origin', $xml->Origin);
		$update->addChild('CallerReference', $xml->CallerReference);

		// Add existing CNAME values
		if ($xml->CNAME)
		{
			$update->addChild('CNAME', $xml->CNAME);
		}

		// Add new CNAME values
		if (isset($opt['CNAME']))
		{
			if (is_array($opt['CNAME']))
			{
				foreach ($opt['CNAME'] as $cname)
				{
					$update->addChild('CNAME', $cname);
				}
			}
			else
			{
				$update->addChild('CNAME', $opt['CNAME']);
			}
		}

		// Comment
		if (isset($opt['Comment']))
		{
			$update->addChild('Comment', $opt['Comment']);
		}
		elseif (isset($xml->Comment))
		{
			$update->addChild('Comment', $xml->Comment);
		}

		// Enabled
		if (isset($opt['Enabled']))
		{
			$update->addChild('Enabled', $opt['Enabled'] ? 'true' : 'false');
		}
		elseif (isset($xml->Enabled))
		{
			$update->addChild('Enabled', $xml->Enabled);
		}

		// Logging
		if (isset($opt['Logging']))
		{
			if (is_array($opt['Logging']))
			{
				$logging = $update->addChild('Logging');
				$bucket_name = $opt['Logging']['Bucket'];

				// Origin
				if (stripos($bucket_name, '.s3.amazonaws.com') !== false)
				{
					$logging->addChild('Bucket', $bucket_name);
				}
				else
				{
					$logging->addChild('Bucket', $bucket_name . '.s3.amazonaws.com');
				}

				$logging->addChild('Prefix', $opt['Logging']['Prefix']);
			}
		}
		elseif (isset($xml->Logging))
		{
			$logging = $update->addChild('Logging');
			$logging->addChild('Bucket',$xml->Logging->Bucket);
			$logging->addChild('Prefix', $xml->Logging->Prefix);
		}

		// Origin Access Identity
		if (isset($opt['OriginAccessIdentity']))
		{
			$update->addChild('OriginAccessIdentity', 'origin-access-identity/cloudfront/' . $opt['OriginAccessIdentity']);
		}
		elseif (isset($xml->OriginAccessIdentity))
		{
			$update->addChild('OriginAccessIdentity', $xml->OriginAccessIdentity);
		}

		// Trusted Signers
		if (isset($opt['TrustedSigners']))
		{
			if (is_array($opt['TrustedSigners']))
			{
				$trusted_signers = $update->addChild('TrustedSigners');
				foreach($opt['TrustedSigners'] as $signer)
				{
					if ($signer == 'Self')
					{
						$trusted_signers->addChild('Self');
					}
					else
					{
						$trusted_signers->addChild('AwsAccountNumber', $signer);
					}
				}
			}
		}
		elseif (isset($xml->TrustedSigners) && $xml->TrustedSigners->count())
		{
			$trusted_signers = $xml->TrustedSigners;
			foreach($xml->TrustedSigners->children() as $signer)
			{
				if ($signer === 'Self')
				{
					$trusted_signers->addChild('Self');
				}
				else
				{
					$trusted_signers->addChild('AWSAccountNumber', $signer);
				}
			}
		}

		// Output
		return $update->asXML();
	}

	/**
	 * Method: remove_cname()
	 * 	Used to remove one or more CNAMEs from a DistributionConfig XML document.
	 *
	 * Access:
	 * 	public
 	 *
	 * Parameters:
	 * 	xml - _SimpleXMLElement_|_ResponseCore_|_string_ (Required) The source DistributionConfig XML to make updates to. Can be the SimpleXMLElement body of a <get_distribution_config()> response, the entire <ResponseCore> of a <get_distribution_config()> response, or a string of XML generated by <generate_config_xml()> or <update_config_xml()>.
	 * 	cname - _string_|_array_ (Optional) This (these) value(s) will be REMOVED from the existing list of CNAME values. To add a CNAME value, see <update_config_xml()>.
	 *
	 * Returns:
	 * 	String DistributionConfig XML document.
 	 *
	 * Examples:
	 * 	example::cloudfront/remove_cname2.phpt:
	 *
	 * See Also:
	 * 	Related - <generate_config_xml()>, <update_config_xml()>, <remove_cname()>
	 */
	public function remove_cname($xml, $cname)
	{
		// If we receive a full ResponseCore object, only use the body.
		if ($xml instanceof ResponseCore)
		{
			$xml = $xml->body;
		}

		// If we received a string of XML, convert it into a SimpleXMLElement object.
		if (is_string($xml))
		{
			$xml = simplexml_load_string($xml);
		}

		// Let's make sure that we have CNAMEs to remove in the first place.
		if (isset($xml->CNAME))
		{
			// If we have an array of CNAME values...
			if (is_array($cname))
			{
				foreach ($cname as $cn)
				{
					for ($i = 0, $length = sizeof($xml->CNAME); $i < $length; $i++)
					{
						if ((string) $xml->CNAME[$i] == $cn)
						{
							unset($xml->CNAME[$i]);
							break;
						}
					}
				}
			}

			// If we only have one CNAME value...
			else
			{
				for ($i = 0, $length = sizeof($xml->CNAME); $i < $length; $i++)
				{
					if ((string) $xml->CNAME[$i] == $cname)
					{
						unset($xml->CNAME[$i]);
						break;
					}
				}
			}
		}

		return $xml->asXML();
	}

	/**
	 * Method: oai_config_xml()
	 * 	Used to generate the Origin Access Identity Config XML used in <create_origin_access_identy()>.
	 *
	 * Access:
	 * 	public
 	 *
	 * Parameters:
	 * 	caller_reference - _string_ (Required) A unique identifier for the request. Must be generated on your own. A time stamp or hash is a good example.
 	 * 	comment - _string_ (Optional) A comment about the origin access identity.
	 *
	 * Returns:
	 * 	String CloudFrontOriginAccessIdentityConfig XML document.
 	 *
	 */
	public function oai_config_xml($caller_reference, $comment = null)
	{
		// Default, empty XML
		$xml = simplexml_load_string(sprintf($this->base_xml, 'CloudFrontOriginAccessIdentityConfig'));

		// CallerReference
		$xml->addChild('CallerReference', $caller_reference);

		// Comment
		if ($comment !== null)
		{
			$xml->addChild('Comment', $comment);
		}

		return $xml->asXML();
	}


	/*%******************************************************************************************%*/
	// DISTRIBUTIONS

	/**
	 * Method: create_distribution()
	 * 	The response echoes the DistributionConfig element and returns other metadata about the distribution. For more information, see Parts of a Basic Distribution. It takes a short time for CloudFront to propagate your new distribution's information throughout the CloudFront system. For more information, see Eventual Consistency. You can have up to 100 distributions in the Amazon CloudFront system.
	 *
	 * 	For an Adobe Real-Time Messaging Protocol (RTMP) streaming distribution, set the Streaming option to true.
	 *
	 * Access:
	 * 	public
 	 *
	 * Parameters:
	 * 	origin - _string_ (Required) The source S3 bucket to use for the CloudFront distribution.
	 * 	caller_reference - _integer_ (Required) A unique identifier for the request. Must be generated on your own. A timestamp could be good.
 	 * 	opt - _array_ (Optional) Associative array of parameters which can have the following keys:
 	 *
 	 * Keys for the $opt parameter:
	 * 	CNAME - _string_|_array_ (Optional) A DNS CNAME to use to map to the CloudFront distribution. If setting more than one, use an indexed array. Supports 1-10 CNAMEs.
	 * 	Comment - _integer_ (Optional) A comment to apply to the distribution. Cannot exceed 128 characters.
	 * 	Enabled - _string_ (Optional) Defaults to true. Use this to set Enabled to false.
	 *	OriginAccessIdentity - _string_ (Optional) The Origin Access Identity associated with this distribution. Use the Identity ID, not the CanonicalId.
	 *	TrustedSigners - _array_ (Optional) Array of AWS Account numbers who are trusted signers. You must explicitly add "Self" (exactly as shown) to the array if you want your own account to be a trusted signer.
	 * 	Streaming - _boolean_ (Optional) Whether this should be for a streaming distribution or not. Defaults to false.
	 * 	returnCurlHandle - _boolean_ (Optional) A private toggle that will return the CURL handle for the request rather than actually completing the request. This is useful for MultiCURL requests.
	 *
	 * Returns:
	 * 	<ResponseCore> object
	 *
	 * Examples:
	 * 	example::cloudfront/create_distribution.phpt:
	 * 	example::cloudfront/create_distribution3.phpt:
	 *
	 * See Also:
	 * 	AWS Method - http://docs.amazonwebservices.com/AmazonCloudFront/latest/DeveloperGuide/CreateDistribution.html
	 * 	Related - <create_distribution()>, <list_distributions()>, <get_distribution_info()>, <delete_distribution()>
	 */
	public function create_distribution($origin, $caller_reference, $opt = null)
	{
		$auth = array();

		if (isset($opt['returnCurlHandle']))
		{
			$auth['returnCurlHandle'] = $opt['returnCurlHandle'];
			unset($opt['returnCurlHandle']);
		}

		if (isset($opt['Streaming']) && $opt['Streaming'] == (bool) true)
		{
			$auth['action'] = 'streaming-distribution';
			unset($opt['Streaming']);
		}
		else
		{
			$auth['action'] = 'distribution';
		}

		$xml = $this->generate_config_xml($origin, $caller_reference, $opt);

		return $this->authenticate(HTTP_POST, null, $auth, $xml, null);
	}

	/**
	 * Method: list_distributions()
	 * 	Gets a list of your distributions. By default, your entire list of distributions is returned in one single page. If the list is long, you can paginate it using the MaxItems and Marker parameters.
	 *
	 * 	Standard distributions are listed separately from streaming distributions. For streaming distributions, set the Streaming option to true.
	 *
	 * Access:
	 * 	public
 	 *
	 * Parameters:
 	 * 	opt - _array_ (Required) Associative array of parameters which can have the following keys:
 	 *
 	 * Keys for the $opt parameter:
	 * 	Marker - _string_ (Optional) Use this when paginating results to indicate where in your list of distributions to begin. The results include distributions in the list that occur after the marker. To get the next page of results, set the Marker to the value of the NextMarker from the current page's response (which is also the ID of the last distribution on that page).
	 * 	MaxItems - _integer_ (Optional) The maximum number of distributions you want in the response body. Maximum of 100.
	 * 	Streaming - _boolean_ (Optional) Whether this should be for a streaming distribution or not. Defaults to false.
	 * 	returnCurlHandle - _boolean_ (Optional) A private toggle that will return the CURL handle for the request rather than actually completing the request. This is useful for MultiCURL requests.
	 *
	 * Returns:
	 * 	<ResponseCore> object
	 *
	 * Examples:
	 * 	example::cloudfront/list_distributions.phpt:
	 * 	example::cloudfront/list_distributions2.phpt:
	 * 	example::cloudfront/list_distributions4.phpt:
	 *
	 * See Also:
	 * 	AWS Method - http://docs.amazonwebservices.com/AmazonCloudFront/latest/DeveloperGuide/ListDistributions.html
	 * 	Related - <create_distribution()>, <list_distributions()>, <get_distribution_info()>, <delete_distribution()>
	 */
	public function list_distributions($opt = null)
	{
		if (isset($opt['Streaming']) && $opt['Streaming'] == (bool) true)
		{
			$opt['action'] = 'streaming-distribution';
			unset($opt['Streaming']);
		}
		else
		{
			$opt['action'] = 'distribution';
		}

		return $this->authenticate(HTTP_GET, null, $opt, null, null);
	}

	/**
	 * Method: get_distribution_info()
	 * 	Gets information about a given distribution.
	 *
	 * 	Standard distributions are handled separately from streaming distributions. For streaming distributions, set the Streaming option to true.
	 *
	 * Access:
	 * 	public
 	 *
	 * Parameters:
 	 * 	distribution_id - _string_ (Required) The distribution ID returned from <create_distribution()> or <list_distributions()>.
 	 * 	opt - _array_ (Required) Associative array of parameters which can have the following keys:
 	 *
 	 * Keys for the $opt parameter:
	 * 	Streaming - _boolean_ (Optional) Whether this should be for a streaming distribution or not. Defaults to false.
	 * 	returnCurlHandle - _boolean_ (Optional) A private toggle that will return the CURL handle for the request rather than actually completing the request. This is useful for MultiCURL requests.
 	 *
	 * Returns:
	 * 	<ResponseCore> object
	 *
	 * Examples:
	 * 	example::cloudfront/get_distribution_info.phpt:
	 * 	example::cloudfront/get_distribution_info3.phpt:
	 *
	 * See Also:
	 * 	AWS Method - http://docs.amazonwebservices.com/AmazonCloudFront/latest/DeveloperGuide/GetDistribution.html
	 * 	Related - <create_distribution()>, <list_distributions()>, <get_distribution_info()>, <delete_distribution()>
	 */
	public function get_distribution_info($distribution_id, $opt = null)
	{
		if (isset($opt['Streaming']) && $opt['Streaming'] == (bool) true)
		{
			$opt['action'] = 'streaming-distribution';
			unset($opt['Streaming']);
		}
		else
		{
			$opt['action'] = 'distribution';
		}

		return $this->authenticate(HTTP_GET, '/' . $distribution_id, $opt, null, null);
	}

	/**
	 * Method: delete_distribution()
	 * 	Deletes a disabled distribution. If you haven't disabled the distribution, Amazon CloudFront returns a DistributionNotDisabled error. Use <set_distribution_config()> to disable a distribution before attempting to delete.
	 *
	 * 	For an Adobe Real-Time Messaging Protocol (RTMP) streaming distribution, set the Streaming option to true.
	 *
	 * Access:
	 * 	public
 	 *
	 * Parameters:
 	 * 	distribution_id - _string_ (Required) The distribution ID returned from <create_distribution()> or <list_distributions()>.
 	 * 	etag - _string_ (Required) The ETag header value retrieved from a call to <get_distribution_config()>.
 	 * 	opt - _array_ (Optional) Associative array of parameters which can have the following keys:
 	 *
 	 * Keys for the $opt parameter:
	 * 	Streaming - _boolean_ (Optional) Whether this should be for a streaming distribution or not. Defaults to false.
	 * 	returnCurlHandle - _boolean_ (Optional) A private toggle that will return the CURL handle for the request rather than actually completing the request. This is useful for MultiCURL requests.
 	 *
	 * Returns:
	 * 	<ResponseCore> object
	 *
	 * Examples:
	 * 	example::cloudfront/z_delete_distribution.phpt:
	 * 	example::cloudfront/z_delete_distribution2.phpt:
	 *
	 * See Also:
	 * 	AWS Method - http://docs.amazonwebservices.com/AmazonCloudFront/latest/DeveloperGuide/DeleteDistribution.html
	 * 	Related - <create_distribution()>, <list_distributions()>, <get_distribution_info()>, <delete_distribution()>
	 */
	public function delete_distribution($distribution_id, $etag = null, $opt = null)
	{
		if (isset($opt['Streaming']) && $opt['Streaming'] == (bool) true)
		{
			$opt['action'] = 'streaming-distribution';
			unset($opt['Streaming']);
		}
		else
		{
			$opt['action'] = 'distribution';
		}

		return $this->authenticate(HTTP_DELETE, '/' . $distribution_id, $opt, null, $etag);
	}

	/**
	 * Method: create_origin_access_identity()
	 * 	The response echoes the CloudFrontOriginAccessIdentity element and returns the newly created identity, an existing identity if the caller_reference is the same, or an error if caller_reference is the same but the rest of the content differs. You can have 100 origin access identities.
	 *
	 * Access:
	 * 	public
 	 *
	 * Parameters:
	 * 	caller_reference - _string_ (Required) A unique identifier for the request. Must be generated on your own. A time stamp or hash is a good example.
 	 * 	comment - _string_ (Optional) A comment about the origin access identity.
 	 *
	 * Returns:
	 * 	<ResponseCore> object
	 *
	 */
	public function create_origin_access_identity($caller_reference, $comment = null)
	{
		$auth = array();
		$auth['action'] = 'origin-access-identity/cloudfront';

		$xml = $this->oai_config_xml($caller_reference, $comment);

		return $this->authenticate(HTTP_POST, null, $auth, $xml, null);
	}


	/*%******************************************************************************************%*/
	// DISTRIBUTION CONFIG

	/**
	 * Method: get_distribution_config()
	 * 	Gets the current distribution config information for a given distribution ID.
	 *
	 * 	Standard distributions are handled separately from streaming distributions. For streaming distributions, set the Streaming option to true.
	 *
	 * Access:
	 * 	public
 	 *
	 * Parameters:
 	 * 	distribution_id - _string_ (Required) The distribution ID returned from <create_distribution()> or <list_distributions()>.
 	 * 	opt - _array_ (Required) Associative array of parameters which can have the following keys:
 	 *
 	 * Keys for the $opt parameter:
	 * 	Streaming - _boolean_ (Optional) Whether this should be for a streaming distribution or not. Defaults to false.
	 * 	returnCurlHandle - _boolean_ (Optional) A private toggle that will return the CURL handle for the request rather than actually completing the request. This is useful for MultiCURL requests.
 	 *
	 * Returns:
	 * 	<ResponseCore> object
	 *
	 * Examples:
	 * 	example::cloudfront/get_distribution_config.phpt:
	 * 	example::cloudfront/get_distribution_config2.phpt:
	 *
	 * See Also:
	 * 	AWS Method - http://docs.amazonwebservices.com/AmazonCloudFront/latest/DeveloperGuide/GetConfig.html
	 * 	Related - <get_distribution_config()>, <set_distribution_config()>
	 */
	public function get_distribution_config($distribution_id, $opt = null)
	{
		if (isset($opt['Streaming']) && $opt['Streaming'] == (bool) true)
		{
			$opt['action'] = 'streaming-distribution';
			unset($opt['Streaming']);
		}
		else
		{
			$opt['action'] = 'distribution';
		}

		return $this->authenticate(HTTP_GET, '/' . $distribution_id . '/config', $opt, null, null);
	}

	/**
	 * Method: set_distribution_config()
	 * 	Sets a new distribution config for a given distribution ID.
	 *
	 * 	Standard distributions are handled separately from streaming distributions. For streaming distributions, set the Streaming option to true.
	 *
	 * Access:
	 * 	public
 	 *
	 * Parameters:
 	 * 	distribution_id - _string_ (Required) The distribution ID returned from <create_distribution()> or <list_distributions()>.
 	 * 	xml - _string_ (Required) The DistributionConfig XML generated by <generate_config_xml()> or <update_config_xml()>.
 	 * 	etag - _string_ (Required) The ETag header value retrieved from a call to <get_distribution_config()>.
 	 * 	opt - _array_ (Required) Associative array of parameters which can have the following keys:
 	 *
 	 * Keys for the $opt parameter:
	 * 	Streaming - _boolean_ (Optional) Whether this should be for a streaming distribution or not. Defaults to false.
	 * 	returnCurlHandle - _boolean_ (Optional) A private toggle that will return the CURL handle for the request rather than actually completing the request. This is useful for MultiCURL requests.
 	 *
	 * Returns:
	 * 	<ResponseCore> object
	 *
	 * Examples:
	 * 	example::cloudfront/set_distribution_config.phpt:
	 * 	example::cloudfront/set_distribution_config3.phpt:
	 *
	 * See Also:
	 * 	AWS Method - http://docs.amazonwebservices.com/AmazonCloudFront/latest/DeveloperGuide/PutConfig.html
	 * 	Related - <get_distribution_config()>, <set_distribution_config()>
	 */
	public function set_distribution_config($distribution_id, $xml, $etag, $opt = null)
	{
		if (isset($opt['Streaming']) && $opt['Streaming'] == (bool) true)
		{
			$opt['action'] = 'streaming-distribution';
			unset($opt['Streaming']);
		}
		else
		{
			$opt['action'] = 'distribution';
		}

		return $this->authenticate(HTTP_PUT, '/' . $distribution_id . '/config', $opt, $xml, $etag);
	}


	/*%******************************************************************************************%*/
	// URLS

	/**
	 * Method: get_private_object_url()
	 * 	Generates a time-limited and/or query signed request for a private file with additional optional restrictions.
	 *
	 * Access:
	 * 	public
 	 *
	 * Parameters:
	 *	filename - _string_ (Required) The filename of the object. Query parameters can be included.
	 *	conditions - _array_ (Required) Associative array of conditions to restrict access. Canned/custom policies are done for you depending on what you specify.
	 *
	 * Keys for the $conditions parameter:
	 *	DateLessThan - _int_ (Required) Time in seconds until the URL expires.
	 *	DateGreaterThan - _int_ (Optional) Time in seconds until the URL becomes valid.
	 *	IpAddress - _string_ (Optional) IP address to restrict the access to.
	 * 	DateLessThanExact - _int_ (Optional) Exact Unix timestamp of expiry time.
	 * 	DateGreaterThanExact - _int_ (Optional) Exact Unix timestamp until URL becomes valid.
	 *
	 * Returns:
	 * 	_string_ The file URL with authentication parameters.
	 *
	 * Examples:
	 * 	example::cloudfront/get_private_object_url.phpt:
	 *
	 * See Also:
	 * 	Serving Private Content - http://docs.amazonwebservices.com/AmazonCloudFront/latest/DeveloperGuide/PrivateContent.html
	 */
	public function get_private_object_url($filename, $conditions)
	{
		// Add this to our request
		$opt = array();
		$opt['domain'] = $this->domain;
		$opt['filename'] = $filename;
		$opt['conditions'] = $conditions;
		$opt['private_key'] = $this->private_key;

		// Authenticate to S3
		$data = $this->authenticate(HTTP_GET,null,$opt);

		return $data['resource']
			. ((strpos($opt['filename'],'?') === false) ? '?' : '&')
			. ((isset($data['policy'])) ? 'Policy=' . $data['policy'] : 'Expires=' . $data['expires'])
			. '&Signature=' . $data['signature']
			. '&Key-Pair-Id=' . $this->key_pair_id;
	}
}
