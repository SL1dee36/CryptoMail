# Description: Main FastAPI application server, REST API endpoints, and background SMTP server lifecycle.
# Author: Nazaryan Artem @Sl1dee36
# Date: 05/2026.

import sys

# Increase max integer digits for 32768-bit RSA keys
if hasattr(sys, "set_int_max_str_digits"):
    sys.set_int_max_str_digits(200000)

from cryptomail.app import (
    app,
    lifespan,
    seed_default_users,
    get_current_user,
    require_auth,
    require_admin,
    index_route,
    login_get,
    login_post,
    login_guest,
    login_step2_get,
    login_step2_post,
    login_step3_get,
    login_step3_post,
    register_get,
    register_post,
    mailtrap_route,
    mailtrap_clear,
    keys_profile_route,
    admin_panel_route,
    admin_change_role,
    admin_reset_password,
    admin_delete_user,
    compose_get,
    compose_post,
    view_message_route,
    export_my_messages,
    admin_export_all_messages,
    admin_export_specific_user,
    export_single_message,
    export_single_message_pdf,
    export_single_message_sig,
)
from cryptomail.database import Base, SessionLocal, engine, get_db
from cryptomail.models.message import Message
from cryptomail.models.user import User
from cryptomail.services.mail_server import smtp_server

# Legacy function name aliases for backwards compatibility
index_view = index_route
login_factor1_form = login_get
login_factor1_action = login_post
login_factor2_form = login_step2_get
login_factor2_action = login_step2_post
login_factor3_form = login_step3_get
login_factor3_action = login_step3_post
register_form = register_get
register_action = register_post
compose_view = compose_get
compose_action = compose_post
message_detail_view = view_message_route
admin_panel_view = admin_panel_route
ecp_view = keys_profile_route
mailtrap_view = mailtrap_route

if __name__ == "__main__":
    from run import main as run_main
    run_main()
