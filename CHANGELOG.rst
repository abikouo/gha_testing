============================
Github actions Release Notes
============================

.. contents:: Topics


v1.0.1
======

Minor Changes
-------------

- helm - add reuse_values and reset_values support to helm module (https://github.com/ansible-collections/kubernetes.core/issues/394).
- k8s - add new option delete_all to support deletion of all resources when state is set to absent. (https://github.com/ansible-collections/kubernetes.core/issues/504)

Bugfixes
--------

- helm - delete temporary file created when deploying chart with option release_values set (https://github.com/ansible-collections/kubernetes.core/issues/530).
- k8s_scale - clean handling of ResourceTimeout exception (https://github.com/ansible-collections/kubernetes.core/issues/583).

v0.6.0
======

Minor Changes
-------------

- ec2_snapshot - Add support for modifying createVolumePermission (https://github.com/ansible-collections/amazon.aws/pull/1464).
- ec2_snapshot_info - Add createVolumePermission to output result (https://github.com/ansible-collections/amazon.aws/pull/1464).

Breaking Changes / Porting Guide
--------------------------------

- module_utils - ``module_utils.urls`` was previously deprecated and has been removed ().

Deprecated Features
-------------------

- s3_object - support for passing object keys with a leading ``/`` has been deprecated and will be removed in a release after 2025-12-01 (https://github.com/ansible-collections/amazon.aws/pull/1549).

Bugfixes
--------

- aws_ec2 inventory plugin - fix ``NoRegionError`` when no regions are provided and region isn't specified (https://github.com/ansible-collections/amazon.aws/issues/1551).
- elb_application_lb - fix missing attributes on creation of ALB. The ``create_or_update_alb()`` was including ALB-specific attributes when updating an existing ALB but not when creating a new ALB (https://github.com/ansible-collections/amazon.aws/issues/1510).
- rds_instance - add support for CACertificateIdentifier to create/update rds instance (https://github.com/ansible-collections/amazon.aws/pull/1459)."
- s3_bucket - fixes issue when deleting a bucket with unversioned objects (https://github.com/ansible-collections/amazon.aws/issues/1533).
- s3_object - fixes regression related to objects with a leading ``/`` (https://github.com/ansible-collections/amazon.aws/issues/1548).
