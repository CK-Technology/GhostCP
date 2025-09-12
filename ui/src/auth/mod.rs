// Authentication management
use leptos::*;
use crate::types::{User, UserRole};
use std::rc::Rc;

#[derive(Debug, Clone)]
pub struct AuthContext {
    pub user: Option<User>,
    pub is_authenticated: bool,
    pub token: Option<String>,
}

impl Default for AuthContext {
    fn default() -> Self {
        Self {
            user: None,
            is_authenticated: false,
            token: None,
        }
    }
}

pub type AuthState = RwSignal<AuthContext>;

pub fn provide_auth_context() -> AuthState {
    let auth_state = create_rw_signal(AuthContext::default());
    provide_context(auth_state);
    auth_state
}

pub fn use_auth() -> AuthState {
    use_context::<AuthState>().expect("AuthContext must be provided")
}

pub fn is_authenticated() -> bool {
    let auth = use_auth();
    auth.get().is_authenticated
}

pub fn current_user() -> Option<User> {
    let auth = use_auth();
    auth.get().user
}

pub fn has_role(role: UserRole) -> bool {
    let user = current_user();
    user.map(|u| matches!((u.role, role), (UserRole::Admin, _) | (r1, r2) if r1 as u8 == r2 as u8))
        .unwrap_or(false)
}

pub fn is_admin() -> bool {
    has_role(UserRole::Admin)
}

pub fn login(user: User, token: String) {
    let auth = use_auth();
    
    // Store token in localStorage
    if let Ok(Some(storage)) = window().local_storage() {
        let _ = storage.set_item("auth_token", &token);
        let _ = storage.set_item("user_data", &serde_json::to_string(&user).unwrap_or_default());
    }
    
    auth.set(AuthContext {
        user: Some(user),
        is_authenticated: true,
        token: Some(token),
    });
}

pub fn logout() {
    let auth = use_auth();
    
    // Clear localStorage
    if let Ok(Some(storage)) = window().local_storage() {
        let _ = storage.remove_item("auth_token");
        let _ = storage.remove_item("user_data");
    }
    
    auth.set(AuthContext::default());
}

pub fn init_auth() {
    let auth = use_auth();
    
    // Try to restore auth state from localStorage
    if let Ok(Some(storage)) = window().local_storage() {
        if let (Ok(Some(token)), Ok(Some(user_data))) = (
            storage.get_item("auth_token"),
            storage.get_item("user_data")
        ) {
            if let Ok(user) = serde_json::from_str::<User>(&user_data) {
                auth.set(AuthContext {
                    user: Some(user),
                    is_authenticated: true,
                    token: Some(token),
                });
            }
        }
    }
}

// Helper to get window object
fn window() -> web_sys::Window {
    web_sys::window().expect("no global `window` exists")
}

// Auth guard component
#[component]
pub fn AuthGuard(
    #[prop(optional)] required_role: Option<UserRole>,
    #[prop(optional)] fallback: Option<View>,
    children: Children,
) -> impl IntoView {
    let auth = use_auth();
    
    create_effect(move |_| {
        let auth_ctx = auth.get();
        
        if !auth_ctx.is_authenticated {
            // Redirect to login
            let navigate = leptos_router::use_navigate();
            navigate("/login", Default::default()).ok();
        }
    });
    
    move || {
        let auth_ctx = auth.get();
        
        if !auth_ctx.is_authenticated {
            fallback.clone().unwrap_or_else(|| {
                view! {
                    <div class="flex items-center justify-center min-h-screen">
                        <div class="text-center">
                            <h2 class="text-2xl font-semibold text-gray-900">
                                "Authentication Required"
                            </h2>
                            <p class="mt-2 text-gray-600">
                                "Please log in to access this page."
                            </p>
                        </div>
                    </div>
                }.into_view()
            })
        } else if let Some(role) = &required_role {
            if let Some(user) = &auth_ctx.user {
                match (&user.role, role) {
                    (UserRole::Admin, _) => children().into_view(), // Admin can access everything
                    (user_role, required_role) if user_role == required_role => children().into_view(),
                    _ => {
                        view! {
                            <div class="flex items-center justify-center min-h-screen">
                                <div class="text-center">
                                    <h2 class="text-2xl font-semibold text-gray-900">
                                        "Access Denied"
                                    </h2>
                                    <p class="mt-2 text-gray-600">
                                        "You don't have permission to access this page."
                                    </p>
                                </div>
                            </div>
                        }.into_view()
                    }
                }
            } else {
                fallback.clone().unwrap_or_else(|| {
                    view! {
                        <div class="flex items-center justify-center min-h-screen">
                            <div class="text-center">
                                <h2 class="text-2xl font-semibold text-gray-900">
                                    "Authentication Required"
                                </h2>
                                <p class="mt-2 text-gray-600">
                                    "Please log in to access this page."
                                </p>
                            </div>
                        </div>
                    }.into_view()
                })
            }
        } else {
            children().into_view()
        }
    }
}