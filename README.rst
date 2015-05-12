===============================================================================
goipa - FreeIPA client library
===============================================================================

goipa is a `FreeIPA <http://www.freeipa.org/>`_ client library written in Go.
It interfaces with the FreeIPA JSON `api <https://git.fedorahosted.org/cgit/freeipa.git/tree/API.txt>`_ 
over HTTPS.

------------------------------------------------------------------------
Usage
------------------------------------------------------------------------

Install using go tools::

    $ go get github.com/ubccr/goipa

Example calling FreeIPA user-show::

    package main

    import (
        "fmt"

        "github.com/ubccr/goipa"
    )

    func main() {
        c := &Client{KeyTab: "/path/to/host.keytab", Host: "ipa.example.com"}

        rec, err := c.UserShow("uid")
        if err != nil {
            panic(err)
        }

        fmt.Println("%s - %s", rec.Uid, rec.UidNumber)
    }

------------------------------------------------------------------------
License
------------------------------------------------------------------------

goipa is released under a BSD style License. See the LICENSE file.
