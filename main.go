package main

import (
	"errors"
	"fmt"
	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/util"
	perrors "github.com/pkg/errors"
	"github.com/samber/lo"
	"github.com/samber/mo"
	"strings"
)

func main() {

	futures := []*mo.Future[string]{
		mo.NewFuture(WrapFuture(func() (string, error) {
			return "", perrors.Wrap(e.w.Update(), "watcher Update failed")
		})),
		mo.NewFuture(WrapFuture(func() (string, error) {
			return "", perrors.Wrap(e.refreshEnforcer(), "refreshEnforcer failed")
		})),
	}
	errors.Join(lo.Map(futures, func(future *mo.Future[string], _ int) error {
		return future.Result().Error()
	})...)

	e, err := casbin.NewEnforcer("./model.conf", "./policy.csv")

	f := func(dRequest, dPolicy string) bool {
		if dPolicy == "*" {
			return true
		}
		return dRequest == dPolicy || strings.HasPrefix(dRequest, dPolicy)
	}
	fe := func(arguments ...any) (any, error) {
		if len(arguments) != 2 {
			return false, nil
		}
		return f(arguments[0].(string), arguments[1].(string)), nil
	}
	e.AddFunction("domainMatch", fe)
	e.AddNamedDomainMatchingFunc("g", "domainMatch", f)

	e.AddNamedMatchingFunc("g2", "KeyMatch2", util.KeyMatch2)

	//sub := "alice"
	//obj := "data1"
	//act := "read"

	sub := "USER/bob"
	//dom := "vip/AFK/"
	dom := "vip/AFK/AFK-cn"
	obj := "RESOURCE/GET/api/vip/item"

	ok, err := e.Enforce(sub, dom, obj)

	if err != nil {
		fmt.Println(err)
		return
	}

	if ok == true {
		fmt.Println("ok")
	} else {
		fmt.Println("not ok")
	}
}
