// Copyright 2014 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package storetesting // import "gopkg.in/juju/charmstore.v5-unstable/internal/storetesting"

import (
	"gopkg.in/juju/charmrepo.v1/testing"
)

var Charms = testing.NewRepo("charm-repo", "quantal")
