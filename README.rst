===============================================================================
goipa - FreeIPA client library
===============================================================================

|godoc|

goipa is a `FreeIPA <http://www.freeipa.org/>`_ client library written in Go.
It interfaces with the FreeIPA JSON `api <https://git.fedorahosted.org/cgit/freeipa.git/tree/API.txt>`_ 
over HTTPS.

------------------------------------------------------------------------
Usage
------------------------------------------------------------------------

Install using go tools::

    $ go get github.com/ubccr/goipa

Example calling FreeIPA user-show:

.. code-block:: go

    package main

    import (
        "fmt"

        "github.com/ubccr/goipa"
    )

    func main() {
        client := ipa.NewDefaultClient()

        err := client.LoginWithKeytab("/path/to/user.keytab", "username")
        if err != nil {
            panic(err)
        }

        rec, err := client.UserShow("uid")
        if err != nil {
            panic(err)
        }

        fmt.Println("%s - %s", rec.Uid, rec.UidNumber)
    }

------------------------------------------------------------------------
License
------------------------------------------------------------------------

goipa is released under a BSD style License. See the LICENSE file.


.. |godoc| image:: https://godoc.org/github.com/golang/gddo?status.svg
    :target: https://godoc.org/github.com/ubccr/goipa
    :alt: Godoc
