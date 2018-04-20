from django.conf import settings
from django.http import HttpResponse
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt

import base64, hmac, hashlib, json

import boto3

# Enforce session to inject credentials
session = boto3.Session(
        aws_access_key_id = settings.AWS_SERVER_PUBLIC_KEY,
        aws_secret_access_key = settings.AWS_SERVER_SECRET_KEY,
)
S3 = session.resource( 's3' )


def add_project_attachements( request ):
    return render( request, 'add_project_attachements.html' )


@csrf_exempt
def success_redirect_endpoint( request ):
    """ This is where the upload will send a POST request after the
    file has been stored in S3.
    """
    return make_response(200)


@csrf_exempt
def handle_s3( request ):
    """ View which handles all POST and DELETE requests sent by Fine Uploader
    S3. You will need to adjust these paths/conditions based on your setup.
    """
    if request.method == "POST":
        return handle_POST(request)
    elif request.method == "DELETE":
        return handle_DELETE(request)
    # add case to handle GET request to return list of files
    else:
        return HttpResponse(status=405)


def handle_POST( request ):
    """ Handle S3 uploader POST requests here. For files <=5MiB this is a simple
    request to sign the policy document. For files >5MiB this is a request
    to sign the headers to start a multipart encoded request.
    """
    class MyEncoder( json.JSONEncoder ):
        """Converts a dict of bytes to Json"""
        def default( self, obj ):
            if isinstance( obj, (bytes, bytearray) ):
                return obj.decode( "ASCII" )  # <- or any other encoding of your choice
            # Let the base class default method raise the TypeError
            return json.JSONEncoder.default( self, obj )

    if request.POST.get( 'success', None ):
        return make_response( 200 )
    else:
        request_payload = json.loads( request.body )
        headers = request_payload.get( 'headers', None )
        if headers:
            # The presence of the 'headers' property in the request payload
            # means this is a request to sign a REST/multipart request
            # and NOT a policy document
            response_data = sign_headers( headers )
        else:
            if not is_valid_policy( request_payload ):
                return make_response( 400, { 'invalid': True } )
            response_data = sign_policy_document( request_payload )
        response_payload = json.dumps( response_data, cls = MyEncoder )
        return make_response( 200, response_payload )


def handle_DELETE( request ):
    """ Handle file deletion requests. For this, we use the Amazon Python SDK, boto.
    """
    if boto3:
        bucket_name = request.GET.get( 'bucket' )
        key_name = request.GET.get( 'key' )
        S3.Object( bucket_name, key_name ).delete()

        return make_response( 200 )
    else:
        return make_response( 500 )


def make_response( status = 200, content = None ):
    """ Construct an HTTP response. Fine Uploader expects 'application/json'.
    """
    response = HttpResponse()
    response.status_code = status
    response[ 'Content-Type' ] = "application/json"
    response.content = content
    return response


def is_valid_policy( policy_document ):
    """ Verify the policy document has not been tampered with client-side
    before sending it off.
    """
    # bucket = settings.AWS_EXPECTED_BUCKET
    # parsed_max_size = settings.AWS_MAX_SIZE
    bucket = ''
    parsed_max_size = 0

    for condition in policy_document[ 'conditions' ]:
        if isinstance( condition, list ) and condition[ 0 ] == 'content-length-range':
            parsed_max_size = condition[ 2 ]
        else:
            if condition.get( 'bucket', None ):
                bucket = condition[ 'bucket' ]

    return bucket == settings.AWS_EXPECTED_BUCKET and int(
            parsed_max_size ) == settings.AWS_MAX_SIZE


def sign_policy_document( policy_document ):
    """ Sign and return the policy doucument for a simple upload.
    http://aws.amazon.com/articles/1434/#signyours3postform
    """
    policy_document_string = str.encode( str( policy_document ) )
    policy = base64.b64encode( policy_document_string )
    aws_secret_key = settings.AWS_CLIENT_SECRET_KEY
    secret_key = str.encode( aws_secret_key )

    signature = base64.b64encode(
            hmac.new( secret_key, policy, hashlib.sha1 ).digest() )
    return {
        'policy'   : policy,
        'signature': signature
    }


def sign_headers( headers ):
    """ Sign and return the headers for a chunked upload. """
    headers_bytes = bytearray( headers, 'utf-8' )  # hmac doesn't want unicode
    aws_client_secret = str.encode( settings.AWS_CLIENT_SECRET_KEY )
    return {
        'signature': base64.b64encode(
                hmac.new( aws_client_secret, headers_bytes, hashlib.sha1 ).digest() )
    }
