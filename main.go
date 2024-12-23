package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"

	"buf.build/go/bufplugin/check"
	"buf.build/go/bufplugin/descriptor"
	"buf.build/go/bufplugin/option"
	"github.com/googleapis/api-linter/lint"
	"github.com/googleapis/api-linter/rules"
	"github.com/jhump/protoreflect/desc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"gopkg.in/yaml.v3"
)

const (
	aipCategoryID        = "AIP"
	aipCoreCategoryID    = "AIP_CORE"
	aipClientLibrariesID = "AIP_CLIENT_LIBRARIES"
)

type fileDescriptorsContextKey struct{}

const configOptionKey = "config_file"

var config *lint.Configs

func main() {
	spec, err := newSpec()
	if err != nil {
		log.Fatalln(err)
	}
	// AIP rules cannot be run in parallel as there is thread-unsafe code in
	// this repository that causes concurrent read and write access to a map.
	check.Main(spec, check.MainWithParallelism(1))
}

func newSpec() (*check.Spec, error) {
	ruleRegistry := lint.NewRuleRegistry()
	if err := rules.Add(ruleRegistry); err != nil {
		return nil, err
	}
	ruleSpecs := make([]*check.RuleSpec, 0, len(ruleRegistry))
	for _, protoRule := range ruleRegistry {
		ruleSpec, err := newRuleSpec(protoRule)
		if err != nil {
			return nil, err
		}
		ruleSpecs = append(ruleSpecs, ruleSpec)
	}
	return &check.Spec{
		Rules: ruleSpecs,
		Categories: []*check.CategorySpec{
			{
				ID:      aipCategoryID,
				Purpose: "Checks all API Enhancement proposals as specified at https://aip.dev.",
			},
			{
				ID:      aipCoreCategoryID,
				Purpose: "Checks all core API Enhancement proposals as specified at https://aip.dev.",
			},
			{
				ID:      aipClientLibrariesID,
				Purpose: "Checks all client library API Enhancement proposals as specified at https://aip.dev.",
			},
		},
		Before: before,
	}, nil
}

func newRuleSpec(protoRule lint.ProtoRule) (*check.RuleSpec, error) {
	ruleName := protoRule.GetName()
	if !ruleName.IsValid() {
		return nil, fmt.Errorf("lint.RuleName is invalid: %q", ruleName)
	}

	split := strings.Split(string(ruleName), "::")
	if len(split) != 3 {
		return nil, fmt.Errorf("unknown lint.RuleName format, expected three parts split by '::' : %q", ruleName)
	}

	categoryIDs := []string{aipCategoryID}
	switch extraCategoryID := split[0]; extraCategoryID {
	case "core":
		categoryIDs = append(categoryIDs, aipCoreCategoryID)
	case "client-libraries":
		categoryIDs = append(categoryIDs, aipClientLibrariesID)
	default:
		return nil, fmt.Errorf("unknown lint.RuleName format: unknown category %q : %q", extraCategoryID, ruleName)
	}

	aipNumber, err := strconv.Atoi(split[1])
	if err != nil {
		return nil, fmt.Errorf("unknown lint.RuleName format, unknown aip %q : %q", split[1], ruleName)
	}

	spec := &check.RuleSpec{
		ID:          getRuleID(string(ruleName)),
		CategoryIDs: categoryIDs,
		Default:     true,
		Purpose:     fmt.Sprintf("Checks AIP rule %s.", ruleName),
		Type:        check.RuleTypeLint,
		Handler:     newRuleHandler(aipNumber, protoRule),
	}
	return spec, nil
}

func getRuleID(name string) string {
	// The allowed characters for RuleName are a-z, 0-9, -.
	// The separator :: is also allowed.
	// We do a translation of these into valid check.Rule IDs.
	split := strings.Split(string(name), "::")
	ruleID := "AIP_" + strings.Join(split[1:3], "_")
	ruleID = strings.ReplaceAll(ruleID, "-", "_")
	ruleID = strings.ToUpper(ruleID)
	return ruleID
}

func newRuleHandler(aip int, protoRule lint.ProtoRule) check.RuleHandler {
	return check.RuleHandlerFunc(
		func(ctx context.Context, responseWriter check.ResponseWriter, request check.Request) error {
			configPath, err := option.GetStringValue(request.Options(), configOptionKey)
			if err != nil {
				return err
			}

			if config == nil {
				if configPath == "" {
					config = &lint.Configs{}
				} else {
					conf, err := lint.ReadConfigsFromFile(configPath)
					if err != nil {
						return err
					}

					config = &conf
				}
			}

			ruleRegistry := lint.NewRuleRegistry()
			ruleRegistry.Register(aip, protoRule)
			linter := lint.New(ruleRegistry, *config)

			fileDescriptors, _ := ctx.Value(fileDescriptorsContextKey{}).([]*desc.FileDescriptor)
			responses, err := linter.LintProtos(fileDescriptors...)
			if err != nil {
				return err
			}

			for _, response := range responses {
				for _, problem := range response.Problems {
					if err := addProblem(responseWriter, problem); err != nil {
						return err
					}
				}
			}

			return nil
		},
	)
}

func addProblem(responseWriter check.ResponseWriter, problem lint.Problem) error {
	msg, err := yaml.Marshal(problem)
	if err != nil {
		return err
	}

	addAnnotationOptions := []check.AddAnnotationOption{
		check.WithMessagef("%s: %s", getRuleID(string(problem.RuleID)), string(msg)),
	}

	descriptor := problem.Descriptor
	if descriptor == nil {
		// This should never happen.
		return errors.New("got nil problem.Descriptor")
	}

	fileDescriptor := descriptor.GetFile()
	if fileDescriptor == nil {
		// If we do not have a FileDescriptor, we cannot report a location.
		responseWriter.AddAnnotation(addAnnotationOptions...)
		return nil
	}
	// If a location is available from the problem, we use that directly.
	if location := problem.Location; location != nil {
		addAnnotationOptions = append(
			addAnnotationOptions,
			check.WithFileNameAndSourcePath(
				fileDescriptor.GetName(),
				protoreflect.SourcePath(location.GetPath()),
			),
		)
	} else {
		// Otherwise we check the source info for the descriptor from the problem.
		if location := descriptor.GetSourceInfo(); location != nil {
			addAnnotationOptions = append(
				addAnnotationOptions,
				check.WithFileNameAndSourcePath(
					fileDescriptor.GetName(),
					protoreflect.SourcePath(location.GetPath()),
				),
			)
		}
	}
	responseWriter.AddAnnotation(addAnnotationOptions...)
	return nil
}

func before(ctx context.Context, request check.Request) (context.Context, check.Request, error) {
	fileDescriptors, err := nonImportFileDescriptorsForFileDescriptors(request.FileDescriptors())
	if err != nil {
		return nil, nil, err
	}
	ctx = context.WithValue(ctx, fileDescriptorsContextKey{}, fileDescriptors)
	return ctx, request, nil
}

func nonImportFileDescriptorsForFileDescriptors(fileDescriptors []descriptor.FileDescriptor) ([]*desc.FileDescriptor, error) {
	if len(fileDescriptors) == 0 {
		return nil, nil
	}
	reflectFileDescriptors := make([]protoreflect.FileDescriptor, 0, len(fileDescriptors))
	for _, fileDescriptor := range fileDescriptors {
		if fileDescriptor.IsImport() {
			continue
		}
		reflectFileDescriptors = append(reflectFileDescriptors, fileDescriptor.ProtoreflectFileDescriptor())
	}
	return desc.WrapFiles(reflectFileDescriptors)
}
