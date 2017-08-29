[![Build Status](https://travis-ci.org/JayKay24/bucket-list-api.svg?branch=develop)](https://travis-ci.org/JayKay24/bucket-list-api)

[![Coverage Status](https://coveralls.io/repos/github/JayKay24/bucket-list-api/badge.svg?branch=develop)](https://coveralls.io/github/JayKay24/bucket-list-api?branch=develop)

# Bucket List Creator API

What would you like to do in the next few year? Climb a mountain? Learn to
ride a bike? It's important to keep track of what you've already done and
what you are yet to achieve.
Bucket List Creator allows you to register and achieve all these feats and
also allow you to tick off what you have done.

### Prerequisites

The requirements are defined in the requirments file

```
requirements.txt
```

### Installing
Install python on your system

On linux:

```
sudo apt install python
```

On Windows:

```
run python-3.6.1.exe
```

Clone the repository using the url:

```
git clone https://github.com/JayKay24/bucket-list-api.git
```

## Usage:

    **POST api/v1/auth/register/**
    * Register with the api
    **POST api/v1/auth/login/**
    * login to the api
    **POST api/v1/bucketlists/**
    * Create a bucketlist
    **PATCH api/v1/bucketlists/<id>**
    * Update a bucketlist
    **GET api/v1/bucketlists/**
    * View your bucketlist(s)
    **DELETE api/v1/bucketlists/<id>**
    * Delete your bucketlist
    **POST api/v1/buckelists/<bkt_id>/bucketlistitems/**
    * Create a bucketlist item
    **PATCH api/v1/bucketlists/<bkt_id>/bucketlistitems/<id>**
    * Update a bucketlist item
    **GET api/v1/bucketlists/<bkt_id>/bucketlistitems/<id>**
    * View a bucketlist item
    **DELETE api/v1/bucketlists/<bkt_id>/bucketlistitems/<id>**
    * Delete a bucketlist item

## Built using

Bucket List Creator api is built using the following tools:

* python version 3.6.1
* Flask version 0.12.2

## Authors

* **James Kinyua Njuguna**

## Acknowledgements

* Python 3.5 documentation
* Flask 0.12.2 documentation
* My Colleagues at Andela
* The internet
