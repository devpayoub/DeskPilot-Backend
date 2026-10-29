from django.contrib import admin

from .models import Department, Membership, Organization


class DepartmentInline(admin.TabularInline):
    model = Department
    fk_name = "organization"
    extra = 0
    fields = ("name", "code", "parent", "is_active")


class MembershipInline(admin.TabularInline):
    model = Membership
    extra = 0
    autocomplete_fields = ("user",)
    fields = ("user", "role", "department", "is_owner", "is_active")


@admin.register(Organization)
class OrganizationAdmin(admin.ModelAdmin):
    list_display = ("name", "slug", "is_active", "created_at")
    search_fields = ("name", "slug")
    prepopulated_fields = {"slug": ("name",)}
    inlines = [DepartmentInline, MembershipInline]


@admin.register(Department)
class DepartmentAdmin(admin.ModelAdmin):
    list_display = ("name", "organization", "code", "parent", "is_active")
    list_filter = ("organization", "is_active")
    search_fields = ("name", "code")


@admin.register(Membership)
class MembershipAdmin(admin.ModelAdmin):
    list_display = ("user", "organization", "role", "department", "status", "is_owner")
    list_filter = ("organization", "role", "is_active")
    search_fields = ("user__email", "user__display_name")
    autocomplete_fields = ("user",)
    readonly_fields = ("invite_token_hash", "invited_at", "accepted_at", "created_at", "updated_at")
