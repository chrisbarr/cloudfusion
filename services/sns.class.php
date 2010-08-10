<?php
/**
 * File: Amazon SNS
 * 	Amazon Simple Notification Service (http://aws.amazon.com/sns)
 *
 * Version:
* 	2010.08.10
 *
 * Copyright:
 * 	2006-2010 Ryan Parman, Foleeo, Inc., and contributors.
 *
 * License:
 * 	Simplified BSD License - http://opensource.org/licenses/bsd-license.php
 *
 * See Also:
 * 	CloudFusion - http://getcloudfusion.com
 * 	Amazon SNS - http://aws.amazon.com/sns
 */


/*%******************************************************************************************%*/
// CONSTANTS

/**
 * Constant: SNS_DEFAULT_URL
 * 	Specify the default notification URL.
 */
define('SNS_DEFAULT_URL', 'sns.us-east-1.amazonaws.com');


/*%******************************************************************************************%*/
// EXCEPTIONS

/**
 * Exception: SNS_Exception
 * 	Default SNS Exception.
 */
class SNS_Exception extends Exception {}


/*%******************************************************************************************%*/
// MAIN CLASS

/**
 * Class: AmazonSNS
 * 	Container for all Amazon SNS-related methods. Inherits additional methods from CloudFusion.
 *
 * Extends:
 * 	CloudFusion
 */
class AmazonSNS extends CloudFusion
{
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
		$this->api_version = '2010-03-31';
		$this->hostname = SNS_DEFAULT_URL;

		if (!$key && !defined('AWS_KEY'))
		{
			throw new SNS_Exception('No account key was passed into the constructor, nor was it set in the AWS_KEY constant.');
		}

		if (!$secret_key && !defined('AWS_SECRET_KEY'))
		{
			throw new SNS_Exception('No account secret was passed into the constructor, nor was it set in the AWS_SECRET_KEY constant.');
		}

		return parent::__construct($key, $secret_key);
	}
	
	/*%******************************************************************************************%*/
	// AUTHENTICATION
	
	public function authenticate($action, $opt = null)
	{
		$method = HTTP_GET;
		
		// Add in required params
		$params['Action'] = $action;
		$params['AWSAccessKeyId'] = $this->key;
		$params['Timestamp'] = gmdate('Y-m-d\TH:i:s\Z');
		$params['SignatureVersion'] = 2;
		$params['SignatureMethod'] = 'HmacSHA256';
		
		// Sort and encode into string
		uksort($params, 'strnatcmp');
		$queryString = '';
		foreach ($params as $key => $val)
		{
			$queryString .= "&{$key}=".rawurlencode($val);
		}
		$queryString = substr($queryString, 1);
		
		// Form request string
		$requestString = $method."\n"
			. $this->hostname."\n"
			. "/\n"
			. $queryString;
		
		// Create signature - Version 2
		$params['Signature'] = base64_encode(
			hash_hmac('sha256', $requestString, $this->secret_key, true)
		);
		
		// Finally create request
		$request_url = 'http://'.$this->hostname.'/?' . http_build_query(
			$params
		);
		
		// Gather information to pass along to other classes.
		$helpers = array(
			'utilities' => $this->utilities_class,
			'request' => $this->request_class,
			'response' => $this->response_class,
		);
		
		// Create request
		$request = new $this->request_class($request_url, $this->set_proxy, $helpers);
		
		// Send!
		$request->send_request();
		
		// Prepare the response
		$headers = $request->get_response_header();
		$headers['x-cloudfusion-requesturl'] = $request_url;
		$headers['x-cloudfusion-stringtosign'] = $requestString;
		$data = new $this->response_class($headers, new SimpleXMLElement($request->get_response_body()), $request->get_response_code());
		
		// Return!
		return $data;
	}
	
	
	/*%******************************************************************************************%*/
	// SUBSCRIPTIONS
	
	public function confirm_subscription($topic_arn, $token, $authenticate_on_unsubscribe = null)
	{
		$opt = array();
		$opt['TopicArn'] = $topic_arn;
		$opt['Token'] = $token;
		
		if(!is_null($authenticate_on_unsubscribe))
		{
			$opt['AuthenticateOnUnsubscribe'] = $authenticate_on_unsubscribe;
		}
		
		return $this->authenticate('ConfirmSubscription', $opt);
	}
	
	public function list_subscriptions($next_token = null)
	{
		$opt = array();
		
		if(!is_null($next_token))
		{
			$opt['NextToken'] = $next_token;
		}
		
		return $this->authenticate('ListSubscriptions', $opt);
	}
	
	public function list_subscriptions_by_topic($topic_arn, $next_token = null)
	{
		$opt = array();
		$opt['TopicArn'] = $topic_arn;
		
		if(!is_null($next_token))
		{
			$opt['NextToken'] = $next_token;
		}
		
		return $this->authenticate('ListSubscriptionsByTopic', $opt);
	}
	
	public function subscribe($topic_arn, $protocol, $endpoint)
	{
		$opt = array();
		$opt['TopicArn'] = $topic_arn;
		$opt['Protocol'] = $protocol;
		$opt['Endpoint'] = $endpoint;
		
		return $this->authenticate('Subscribe', $opt);
	}
	
	public function unsubscribe($subscription_arn)
	{
		$opt = array();
		$opt['SubscriptionArn'] = $subscription_arn;
		
		return $this->authenticate('Unsubscribe', $opt);
	}
	
	
	/*%******************************************************************************************%*/
	// TOPICS
	
	public function create_topic($name)
	{
		$opt = array();
		$opt['Name'] = $name;
		
		return $this->authenticate('CreateTopic', $opt);
	}
	
	public function delete_topic($topic_arn)
	{
		$opt = array();
		$opt['TopicArn'] = $topic_arn;
		
		return $this->authenticate('DeleteTopic', $opt);
	}
	
	public function get_topic_attributes($topic_arn)
	{
		$opt = array();
		$opt['TopicArn'] = $topic_arn;
		
		return $this->authenticate('GetTopicAttributes', $opt);
	}
	
	public function list_topics($next_token = null)
	{
		$opt = array();
		
		if(!is_null($next_token))
		{
			$opt['NextToken'] = $next_token;
		}
		
		return $this->authenticate('ListTopics', $opt);
	}
	
	public function set_topic_attributes($topic_arn, $attribute_name, $attribute_value)
	{
		$opt = array();
		$opt['TopicArn'] = $topic_arn;
		$opt['AttributeName'] = $attribute_name;
		$opt['AttributeValue'] = $attribute_value;
		
		return $this->authenticate('SetTopicAttributes', $opt);
	}
	
	public function publish($topic_arn, $message, $subject = null)
	{
		$opt = array();
		$opt['TopicArn'] = $topic_arn;
		$opt['Message'] = $message;
		
		if(!is_null($subject))
		{
			$opt['Subject'] = $subject;
		}
		
		return $this->authenticate('Publish', $opt);
	}
	
	
	/*%******************************************************************************************%*/
	// PERMISSIONS
	
	public function add_permission($topic_arn, $label, $permissions = array())
	{
		$opt = array();
		$opt['TopicArn'] = $topic_arn;
		$opt['Label'] = $label;
		
		$x = 1;
		
		// Construct permissions
		foreach($permissions as $account_id => $permission)
		{
			// Check if $permission is array of permissions
			if(is_array($permission))
			{
				for($y = 0; $y < count($permission); $y++)
				{
					$opt['AWSAccountId.member.'.$x] = $account_id;
					$opt['ActionName.member.'.$x] = $permission[$y];
					
					$x++;
				}
			}
			else
			{
				$opt['AWSAccountId.member.'.$x] = $account_id;
				$opt['ActionName.member.'.$x] = $permission;
				
				$x++;
			}
		}
		
		return $this->authenticate('AddPermission', $opt);
	}
	
	public function remove_permission($topic_arn, $label)
	{
		$opt = array();
		$opt['TopicArn'] = $topic_arn;
		$opt['Label'] = $label;
		
		return $this->authenticate('RemovePermission', $opt);
	}
}
