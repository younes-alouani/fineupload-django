from django.conf.urls import url
from videos.controllers.video_create_controller import video_create_form, handle_s3, success_redirect_endpoint


urlpatterns = [
    url( r'^video-create-form/$', video_create_form, name = 'video_create_form' ),
    url( r'^s3/signature', handle_s3, name = "s3_signee" ),
    url( r'^s3/delete', handle_s3, name = 's3_delete' ),
    url( r'^s3/success', success_redirect_endpoint, name = "s3_succes_endpoint" )
]
