.. VaultAPI documentation master file, created by
   sphinx-quickstart on Tue Sep 17 09:22:11 2024.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to VaultAPI's documentation!
====================================

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   README

VaultAPI - Server
=================

.. automodule:: vaultapi.server

====

.. automodule:: vaultapi.api

Authenticator
=============
.. automodule:: vaultapi.auth

Database
========
.. automodule:: vaultapi.database

Exceptions
==========
.. automodule:: vaultapi.exceptions

Models
======

.. autoclass:: vaultapi.models.RateLimit(BaseModel)
   :exclude-members: _abc_impl, model_config, model_fields, model_computed_fields

====

.. autoclass:: vaultapi.models.Session(BaseModel)
   :exclude-members: _abc_impl, model_config, model_fields, model_computed_fields

====

.. autoclass:: vaultapi.models.EnvConfig(BaseSettings)
   :exclude-members: _abc_impl, model_config, model_fields, model_computed_fields

====

.. automodule:: vaultapi.models
   :exclude-members: RateLimit, Session, EnvConfig

Payload
=======

.. autoclass:: vaultapi.payload.DeleteSecret(BaseModel)
   :exclude-members: _abc_impl, model_config, model_fields, model_computed_fields

====

.. autoclass:: vaultapi.payload.PutSecret(BaseModel)
   :exclude-members: _abc_impl, model_config, model_fields, model_computed_fields

RateLimit
=========

.. automodule:: vaultapi.rate_limit

API Routes
==========

.. automodule:: vaultapi.routes

Transit
=======

.. automodule:: vaultapi.transit

Util
====

.. automodule:: vaultapi.util

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
