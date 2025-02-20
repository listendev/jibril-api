// Package types contains all the types used in the project and exported for other packages to use it.
// The Agent:
// it contains all information about the machine (or container) will run the pipeline, it also has info
// about the context of the pipeline and other metadata. The `context_id` is the row associated with
// the table of the context of the column `kind`.
// For example: the agent having kind=github and context_id=1, it means that you need to fetch the
// context from github table with id=1.
//
// The Context:
// it contains all the information about the context of the pipeline, it could be a GitHub event, GitLab,
// K8s or whatever, it is a separated table to keep the context of the pipeline, every kind of context
// have different fields, so we need to keep it separated.
//
// The Event:
// now it can have only what really need for the event, it also have the reference to the agent that generates
// the event, so we can know where the event comes from.
package types
