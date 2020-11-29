# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2018 Tan Kean Siong
#
# SPDX-License-Identifier: GPL-2.0-or-later

from dionaea.core import ihandler, incident, g_dionaea
from dionaea import IHandlerLoader

import logging
import socket
import boto3

logger = logging.getLogger('s3')
logger.setLevel(logging.DEBUG)


class S3HandlerLoader(IHandlerLoader):
    name = "s3"

    @classmethod
    def start(cls, config=None):
        return s3handler("*", config=config)


class s3handler(ihandler):
    def __init__(self, path, config=None):
        logger.debug("%s ready!" % (self.__class__.__name__))
        ihandler.__init__(self, path)

        self.bucket_name = config.get("bucket_name")
        self.region_name = config.get("region_name")
        self.access_key_id = config.get("access_key_id")
        self.secret_access_key = config.get("secret_access_key")
        self.endpoint_url = config.get("endpoint_url")
        self.verify = config.get("verify")
        self.s3_dest_folder = config.get("s3_dest_folder")
        self.s3 = ''


    def handle_incident(self, icd):
        pass

    def handle_incident_dionaea_download_complete_unique(self, icd):

        # Dionaea will upload unique samples to Amazon S3 bucket with Boto3 (AWS SDK Python)
        # Create an S3 client
        try:
            self.s3 = boto3.client(
                    's3',
                    self.region_name,
                    aws_access_key_id=self.access_key_id,
                    aws_secret_access_key=self.secret_access_key,
                    endpoint_url=self.endpoint_url or None,
                    verify=self.verify)

            # Uploads the given file using a Boto 3 managed uploader, which will split up large
            # files automatically and upload parts in parallel.
            self.s3.upload_file(icd.file, self.bucket_name, self.s3_dest_folder+icd.md5hash)
            logger.info("File (MD5) uploaded to S3 bucket: {0}".format(icd.md5hash))

        except Exception as e:
            logger.warn("S3 exception: {0}".format(e))
