// Copyright 2020-2025 Politecnico di Torino
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package tenantwh groups the functionalities related to the Tenant webhook.
package tenantwh

import (
	"context"
	"fmt"
	"reflect"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	clv1alpha1 "github.com/netgroup-polito/CrownLabs/operators/api/v1alpha1"
	clv1alpha2 "github.com/netgroup-polito/CrownLabs/operators/api/v1alpha2"
	"github.com/netgroup-polito/CrownLabs/operators/pkg/utils"
)

// LastLoginToleration defines the maximum skew with respect to the current time that is accepted by the webhook for the LastLogin field.
const LastLoginToleration = time.Hour * 24

// TenantValidator validates Tenants.
type TenantValidator struct {
	TenantWebhook
	admission.CustomValidator
}

// HandleSelfEdit checks every field but public keys for changes:
// - LastLogin must be within a certain tolerance;
// - Workspaces can be changed only if autoenroll is enabled and within the allowed roles;
// - Other fields must be unchanged.
func (tv *TenantValidator) HandleSelfEdit(ctx context.Context, newTenant, oldTenant *clv1alpha2.Tenant) (admission.Warnings, error) {
	log := ctrl.LoggerFrom(ctx)
	newTenant.Spec.PublicKeys = nil
	oldTenant.Spec.PublicKeys = nil

	lastLoginDelta := time.Until(newTenant.Spec.LastLogin.Time).Abs()
	if newTenant.Spec.LastLogin != oldTenant.Spec.LastLogin && lastLoginDelta > LastLoginToleration {
		return nil, errors.NewForbidden(schema.GroupResource{}, newTenant.Name, fmt.Errorf("you are not allowed to change the LastLogin field in the owned tenant, or the change is not valid: %s", lastLoginDelta))
	}
	newTenant.Spec.LastLogin = metav1.Time{}
	oldTenant.Spec.LastLogin = metav1.Time{}

	// manage workspaces
	newWorkspaces := newTenant.Spec.Workspaces
	oldWorkspaces := oldTenant.Spec.Workspaces
	newTenant.Spec.Workspaces = nil
	oldTenant.Spec.Workspaces = nil

	if !reflect.DeepEqual(newTenant.Spec, oldTenant.Spec) {
		log.Info("denied: unexpected tenant spec change")
		return nil, errors.NewForbidden(schema.GroupResource{}, newTenant.Name, fmt.Errorf("unexpected tenant spec change, only lastLogintime and self-enrolling workspaces are allowed to change"))
	}

	newTenant.Spec.Workspaces = newWorkspaces
	oldTenant.Spec.Workspaces = oldWorkspaces

	res, err := tv.checkValidWorkspaces(ctx, newTenant, oldTenant)
	if err != nil {
		log.Error(err, "failed to check workspace changes")
		return nil, errors.NewInternalError(fmt.Errorf("failed to check workspace changes: %w", err))
	}
	if !res {
		log.Info("denied: workspaces validation failed")
		return nil, errors.NewForbidden(schema.GroupResource{}, newTenant.Name, fmt.Errorf("you are not allowed to change your own workspaces"))
	}

	log.Info("allowed")
	return nil, nil
}

// checkValidWorkspaces checks that the user is not changing workspaces they are not allowed to change.
func (tv *TenantValidator) checkValidWorkspaces(ctx context.Context, newTenant, oldTenant *clv1alpha2.Tenant) (bool, error) {
	workspaceDiff := CalculateWorkspacesDiff(newTenant, oldTenant)
	newWorkspacesMap := mapFromWorkspacesList(newTenant)

	for ws, changed := range workspaceDiff {
		if !changed {
			// it's always ok to keep the same role
			continue
		}
		wsObj := clv1alpha1.Workspace{}
		err := tv.Client.Get(ctx, client.ObjectKey{Name: ws}, &wsObj)
		if err != nil {
			return false, fmt.Errorf("failed to fetch workspace %s: %w", ws, err)
		}
		if !utils.AutoEnrollEnabled(wsObj.Spec.AutoEnroll) {
			// Tenant cannot change workspaces with autoenroll disabled
			return false, nil
		}
		if _, ok := newWorkspacesMap[ws]; !ok {
			// it's always possible to remove a Workspace from the Tenant if the target Workspace has autoenroll enabled
			continue
		}
		if wsObj.Spec.AutoEnroll == clv1alpha1.AutoenrollImmediate && newWorkspacesMap[ws] != clv1alpha2.User {
			// if AutoEnroll is Immediate, then the user has to enroll with User role
			return false, nil
		}
		if wsObj.Spec.AutoEnroll == clv1alpha1.AutoenrollWithApproval && newWorkspacesMap[ws] != clv1alpha2.Candidate {
			// if AutoEnroll is WithApproval, then the user has to enroll with Candidate role (to be approved by a Manager)
			return false, nil
		}
	}

	return true, nil
}

// HandleWorkspaceEdit checks that changes made to the workspaces have been made by a valid manager, then checks other fields not to have been modified through DeepEqual.
func (tv *TenantValidator) HandleWorkspaceEdit(ctx context.Context, newTenant, oldTenant, manager *clv1alpha2.Tenant, operation admissionv1.Operation) (admission.Warnings, error) {
	log := ctrl.LoggerFrom(ctx)

	workspacesDiff := CalculateWorkspacesDiff(newTenant, oldTenant)
	managerWorkspaces := mapFromWorkspacesList(manager)

	for ws, changed := range workspacesDiff {
		if changed && managerWorkspaces[ws] != clv1alpha2.Manager {
			log.Info("denied: unexpected tenant spec change", "not-a-manager-for", ws)
			return nil, errors.NewForbidden(schema.GroupResource{}, newTenant.Name, fmt.Errorf("you are not a manager for workspace %s, so you cannot change it in the tenant", ws))
		}
	}

	newTenant.Spec.Workspaces = nil
	oldTenant.Spec.Workspaces = nil
	if operation != admissionv1.Create && !reflect.DeepEqual(newTenant.Spec, oldTenant.Spec) {
		log.Info("denied: unexpected tenant spec change")
		return nil, errors.NewForbidden(schema.GroupResource{}, newTenant.Name, fmt.Errorf("only changes to workspaces are allowed in the tenant"))
	}

	log.Info("allowed")
	return nil, nil
}

func calculateWorkspacesOneWayDiff(a, b *clv1alpha2.Tenant, changes map[string]bool) map[string]bool {
	aAsMap := mapFromWorkspacesList(a)
	for _, v := range b.Spec.Workspaces {
		if aAsMap[v.Name] != v.Role {
			changes[v.Name] = true
		}
	}
	return changes
}

// CalculateWorkspacesDiff returns the list of workspaces that are different between two tenants.
func CalculateWorkspacesDiff(a, b *clv1alpha2.Tenant) map[string]bool {
	changes := calculateWorkspacesOneWayDiff(a, b, map[string]bool{})

	return calculateWorkspacesOneWayDiff(b, a, changes)
}

func mapFromWorkspacesList(tenant *clv1alpha2.Tenant) map[string]clv1alpha2.WorkspaceUserRole {
	wss := make(map[string]clv1alpha2.WorkspaceUserRole, len(tenant.Spec.Workspaces))

	for _, v := range tenant.Spec.Workspaces {
		wss[v.Name] = v.Role
	}

	return wss
}

func (tv *TenantValidator) ValidatePreflight(ctx context.Context, newObj, oldObj runtime.Object, op admissionv1.Operation) (newTenant, oldTenant *clv1alpha2.Tenant, warnings admission.Warnings, req admission.Request, newCtx context.Context, stopEarly bool, err error) {

	var ok bool
	stopEarly = true
	newTenant, ok = newObj.(*clv1alpha2.Tenant)
	warnings = admission.Warnings{}

	log := ctrl.LoggerFrom(ctx).WithValues("tenant", newTenant.Name, "operation", op)
	log.Info("processing admission request")
	newCtx = ctrl.LoggerInto(ctx, log)

	if !ok {
		err = fmt.Errorf("expected a Tenant object, got %T", newObj)
		return
	}

	if op != admissionv1.Update {
		oldTenant = &clv1alpha2.Tenant{}
	} else {
		oldTenant, ok = oldObj.(*clv1alpha2.Tenant)
		if !ok && op != admissionv1.Create {
			err = fmt.Errorf("expected a Tenant object, got %T", oldObj)
			return
		}
	}

	req, err = admission.RequestFromContext(ctx)
	if err != nil {
		return
	}

	if tv.CheckWebhookOverride(&req) {
		log.Info("admitted: successful override")
		warnings = append(warnings, "webhook check overridden")
		return
	}

	stopEarly = false
	return
}

func (tv *TenantValidator) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {

	tenant, _oldT, warnings, req, ctx, stopEarly, err := tv.ValidatePreflight(ctx, obj, nil, admissionv1.Create)
	log := ctrl.LoggerFrom(ctx)

	if err != nil {
		log.Error(err, "failed preflight validation")
		return warnings, fmt.Errorf("preflight validation failed: %w", err)
	}
	if stopEarly {
		log.Info("skipping validation for create operation")
		return warnings, nil
	}

	manager, err := tv.GetClusterTenant(ctx, req.UserInfo.Username)
	if err != nil {
		log.Error(err, "failed fetching a (manager) tenant associated to the current actor")
		return nil, fmt.Errorf("could not fetch a tenant for the current user: %w", err)
	}

	return tv.HandleWorkspaceEdit(ctx, tenant, _oldT, manager, req.Operation)
}

func (tv *TenantValidator) ValidateUpdate(ctx context.Context, newObj, oldObj runtime.Object) (admission.Warnings, error) {
	newTenant, oldTenant, warnings, req, ctx, stopEarly, err := tv.ValidatePreflight(ctx, newObj, oldObj, admissionv1.Update)
	log := ctrl.LoggerFrom(ctx)
	if err != nil {
		log.Error(err, "failed preflight validation")
		return warnings, fmt.Errorf("preflight validation failed: %w", err)
	}
	if stopEarly {
		log.Info("skipping validation for update operation")
		return warnings, nil
	}

	if req.UserInfo.Username == req.Name {
		ctx = ctrl.LoggerInto(ctx, log.WithValues("operation", "self-edit"))
		return tv.HandleSelfEdit(ctx, newTenant, oldTenant)
	}

	manager, err := tv.GetClusterTenant(ctx, req.UserInfo.Username)
	if err != nil {
		log.Error(err, "failed fetching a (manager) tenant associated to the current actor")
		return nil, fmt.Errorf("could not fetch a tenant for the current user: %w", err)
	}

	return tv.HandleWorkspaceEdit(ctx, newTenant, oldTenant, manager, req.Operation)
}

func (tv *TenantValidator) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {

	tenant, ok := obj.(*clv1alpha2.Tenant)
	if !ok {
		return nil, fmt.Errorf("expected a Tenant object, got %T", obj)
	}

	ctrl.LoggerFrom(ctx).WithValues("tenant", tenant.Name, "operation", admissionv1.Delete).Info("allowed")
	return nil, nil
}
