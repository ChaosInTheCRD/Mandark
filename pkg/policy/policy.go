package policy

import (
	"context"
	"fmt"
	"sync"
  "errors"
  "encoding/json"

	"github.com/chaosinthecrd/mandark/pkg/config"
	"github.com/google/go-containerregistry/pkg/name"
	sigstorewebhook "github.com/sigstore/policy-controller/pkg/webhook"
	sigstorepolicy "github.com/sigstore/policy-controller/pkg/webhook/clusterimagepolicy"
  "github.com/sigstore/cosign/pkg/cosign"
  "github.com/sigstore/cosign/pkg/policy"
)


func VerifyImages(cip sigstorepolicy.ClusterImagePolicy, refs config.Images) (*[]sigstorewebhook.PolicyResult, []error) {

  ctx := context.TODO()

  results := []sigstorewebhook.PolicyResult{}

  for _, n := range(refs.ImageReferences) {
    result, err := ValidatePolicy(ctx, n, cip)
    if err != nil {
      panic(err)
      return &results, err
    }

    fmt.Printf("Result: %v", result)
    results = append(results, *result)
  }

  fmt.Printf("Result: %v", results)
  return &results, nil
}


func ValidatePolicy(ctx context.Context, ref name.Reference, cip sigstorepolicy.ClusterImagePolicy) (*sigstorewebhook.PolicyResult, []error) {

	// Each gofunc creates and puts one of these into a results channel.
	// Once each gofunc finishes, we go through the channel and pull out
	// the results.
	type retChannelType struct {
		name         string
		static       bool
		attestations map[string][]sigstorewebhook.PolicyAttestation
		signatures   []sigstorewebhook.PolicySignature
		err          error
	}
	wg := new(sync.WaitGroup)

	results := make(chan retChannelType, len(cip.Authorities))
	for _, authority := range cip.Authorities {

		authority := authority // due to gofunc
		// logs.Debugf("Checking Authority: %s", authority.Name)

		wg.Add(1)
		go func() {
			defer wg.Done()
			result := retChannelType{name: authority.Name}

			switch {
			case authority.Static != nil:
				if authority.Static.Action == "fail" {
					result.err = cosign.NewVerificationError("disallowed by static policy")
					results <- result
					return
				}
				result.static = true

			case len(authority.Attestations) > 0:
				// We're doing the verify-attestations path, so validate (.att)
				result.attestations, result.err = sigstorewebhook.ValidatePolicyAttestationsForAuthority(ctx, ref, authority)

			default:
				result.signatures, result.err = sigstorewebhook.ValidatePolicySignaturesForAuthority(ctx, ref, authority)
			}
			results <- result
		}()
	}

	// If none of the Authorities for a given policy pass the checks, gather
	// the errors here. Even if there are errors, return the matched
	// authoritypolicies.
	authorityErrors := make([]error, 0, len(cip.Authorities))
	// We collect all the successfully satisfied Authorities into this and
	// return it.
	policyResult := &sigstorewebhook.PolicyResult{
		AuthorityMatches: make(map[string]sigstorewebhook.AuthorityMatch, len(cip.Authorities)),
	}
	for range cip.Authorities {
		select {
		case <-ctx.Done():
			authorityErrors = append(authorityErrors, fmt.Errorf("%w before validation completed", ctx.Err()))

		case result, ok := <-results:
			if !ok {
				authorityErrors = append(authorityErrors, errors.New("results channel closed before all results were sent"))
				continue
			}
			switch {
			case result.err != nil:
				// We only wrap actual policy failures as FieldErrors with the
				// possibly Warn level. Other things imho should be still
				// be considered errors.
				authorityErrors = append(authorityErrors, result.err)

			case len(result.signatures) > 0:
				policyResult.AuthorityMatches[result.name] = sigstorewebhook.AuthorityMatch{Signatures: result.signatures}

			case len(result.attestations) > 0:
				policyResult.AuthorityMatches[result.name] = sigstorewebhook.AuthorityMatch{Attestations: result.attestations}

			case result.static:
				// This happens when we encounter a policy with:
				//   static:
				//     action: "pass"
				policyResult.AuthorityMatches[result.name] = sigstorewebhook.AuthorityMatch{
					Static: true,
				}

			default:
				authorityErrors = append(authorityErrors, fmt.Errorf("failed to process authority: %s", result.name))
			}
		}
	}
	wg.Wait()
	// Even if there are errors, return the policies, since as per the
	// spec, we just need one authority to pass checks. If more than
	// one are required, that is enforced at the CIP policy level.
	// If however there are no authorityMatches, return nil so we don't have
	// to keep checking the length on the returned calls.
	if len(policyResult.AuthorityMatches) == 0 {
		return nil, authorityErrors
	}
	// Ok, there's at least one valid authority that matched. If there's a CIP
	// level policy, validate it here before returning.
	if cip.Policy != nil {
		// logging.FromContext(ctx).Info("Validating CIP level policy")
		policyJSON, err := json.Marshal(policyResult)
		if err != nil {
			return nil, append(authorityErrors, err)
		}
		err = policy.EvaluatePolicyAgainstJSON(ctx, "ClusterImagePolicy", cip.Policy.Type, cip.Policy.Data, policyJSON)
		if err != nil {
			// logging.FromContext(ctx).Warnf("Failed to validate CIP level policy against %s", string(policyJSON))
			return nil, append(authorityErrors, err)
		}
	}
	return policyResult, authorityErrors
}
