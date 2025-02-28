package types

import (
	"net/url"
	"strconv"
)

type Page[T any] struct {
	Items    []T      `json:"items"`
	PageInfo PageInfo `json:"pageInfo"`
}

type PageInfo struct {
	HasNextPage bool    `json:"hasNextPage"`
	EndCursor   *Cursor `json:"endCursor"`
	HasPrevPage bool    `json:"hasPrevPage"`
	StartCursor *Cursor `json:"startCursor"`
}

type Cursor string

type PageArgs struct {
	First  *uint   `json:"first,omitempty"`
	After  *Cursor `json:"after,omitempty"`
	Last   *uint   `json:"last,omitempty"`
	Before *Cursor `json:"before,omitempty"`
}

// DecodePageArgs extracts PageArgs from URL query parameters.
func DecodePageArgs(v url.Values) PageArgs {
	var first *uint
	f := v.Get("first")
	if f != "" {
		ff, err := strconv.ParseUint(f, 10, 64)
		if err != nil {
			panic(err)
		}
		uFirst := uint(ff)
		first = &uFirst
	}

	var last *uint
	l := v.Get("last")
	if l != "" {
		ll, err := strconv.ParseUint(l, 10, 64)
		if err != nil {
			panic(err)
		}
		uLast := uint(ll)
		last = &uLast
	}

	var before *Cursor
	b := v.Get("before")
	if b != "" {
		bf := Cursor(b)
		before = &bf
	}

	var after *Cursor
	a := v.Get("after")
	if a != "" {
		af := Cursor(a)
		after = &af
	}

	return PageArgs{
		First:  first,
		After:  after,
		Last:   last,
		Before: before,
	}
}
