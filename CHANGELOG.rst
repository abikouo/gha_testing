============================
Github actions Release Notes
============================

.. contents:: Topics


v0.1.0
======

Minor Changes
-------------

- helm - add reuse_values and reset_values support to helm module (https://github.com/ansible-collections/kubernetes.core/issues/394).
- k8s - add new option delete_all to support deletion of all resources when state is set to absent. (https://github.com/ansible-collections/kubernetes.core/issues/504)

Bugfixes
--------

- helm - delete temporary file created when deploying chart with option release_values set (https://github.com/ansible-collections/kubernetes.core/issues/530).
- k8s_scale - clean handling of ResourceTimeout exception (https://github.com/ansible-collections/kubernetes.core/issues/583).
