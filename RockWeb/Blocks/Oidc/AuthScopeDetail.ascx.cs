// <copyright>
// Copyright by the Spark Development Network
//
// Licensed under the Rock Community License (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.rockrms.com/license
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// </copyright>
//
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Text;
using System.Web.UI;
using DocumentFormat.OpenXml.Office.CustomXsn;
using Rock;
using Rock.Constants;
using Rock.Data;
using Rock.Model;
using Rock.Security;
using Rock.Web.Cache;
using Rock.Web.UI;

namespace RockWeb.Blocks.Oidc
{
    [DisplayName( "Open Id Connect Scope Detail" )]
    [Category( "Oidc" )]
    [Description( "Displays the details of the given Open Id Connect Scope." )]
    public partial class AuthScopeDetail : Rock.Web.UI.RockBlock, IDetailBlock
    {
        private class PageParameterKeys
        {
            public const string ScopeId = "ScopeId";
        }

        #region Control Methods

        /// <summary>
        /// Raises the <see cref="E:System.Web.UI.Control.Load" /> event.
        /// </summary>
        /// <param name="e">The <see cref="T:System.EventArgs" /> object that contains the event data.</param>
        protected override void OnLoad( EventArgs e )
        {
            base.OnLoad( e );

            if ( !Page.IsPostBack )
            {
                var scopeId = PageParameter( PageParameterKeys.ScopeId ).AsIntegerOrNull();
                if ( scopeId == null )
                {
                    DisplayErrorMessage( "No Auth Scope Id was specified." );
                    return;
                }

                ShowDetail( scopeId.Value );
            }
        }

        #endregion

        #region Events

        /// <summary>
        /// Handles the Click event of the lbSave control.
        /// </summary>
        /// <param name="sender">The source of the event.</param>
        /// <param name="e">The <see cref="EventArgs"/> instance containing the event data.</param>
        protected void lbSave_Click( object sender, EventArgs e )
        {
            var scopeId = PageParameter( PageParameterKeys.ScopeId ).AsIntegerOrNull();
            if ( scopeId == null )
            {
                DisplayErrorMessage( "No Auth Scope Id was specified." );
                return;
            }

            SaveAuthScope( scopeId.Value );
            NavigateToParentPage();
        }

        private void SaveAuthScope( int authScopeId )
        {
            var isNew = authScopeId.Equals( 0 );

            var authScope = new AuthScope();

            var editAllowed = authScope.IsAuthorized( Authorization.EDIT, CurrentPerson );
            if ( !editAllowed )
            {
                DisplayErrorMessage( "The current user is not authorized to make changes." );
                return;
            }

            var rockContext = new RockContext();
            var authScopeService = new AuthScopeService( rockContext );
            if ( isNew )
            {
                authScopeService.Add( authScope );
            }
            else
            {
                authScope = authScopeService.Get( authScopeId );
            }

            if(authScope == null )
            {
                DisplayErrorMessage( "The Auth Scope with the specified Id was found." );
                return;
            }

            if ( !authScope.IsSystem )
            {
                authScope.Name = tbName.Text;
            }
            authScope.PublicName = tbPublicName.Text;
            authScope.IsActive = cbActive.Checked;

            rockContext.SaveChanges();
        }

        /// <summary>
        /// Handles the Click event of the lbCancel control.
        /// </summary>
        /// <param name="sender">The source of the event.</param>
        /// <param name="e">The <see cref="EventArgs"/> instance containing the event data.</param>
        protected void lbCancel_Click( object sender, EventArgs e )
        {
            NavigateToParentPage();
        }
        #endregion

        #region Internal Methods
        private void DisplayErrorMessage( string message )
        {
            nbWarningMessage.Text = message;
            nbWarningMessage.NotificationBoxType = Rock.Web.UI.Controls.NotificationBoxType.Danger;
            nbWarningMessage.Visible = true;
            pnlEditDetails.Visible = false;
        }

        /// <summary>
        /// Shows the detail.
        /// </summary>
        /// <param name="authScopeId">The rest user identifier.</param>
        public void ShowDetail( int authScopeId )
        {
            var rockContext = new RockContext();

            AuthScope authScope = null;
            var isNew = authScopeId.Equals( 0 );
            if ( !isNew )
            {
                authScope = new AuthScopeService( rockContext ).Get( authScopeId );
                lTitle.Text = ActionTitle.Edit( "Scope" ).FormatAsHtmlTitle();
            }
            else
            {
                lTitle.Text = ActionTitle.Add( "Scope" ).FormatAsHtmlTitle();
            }

            if ( authScope == null )
            {
                if ( !isNew )
                {
                    DisplayErrorMessage( "The Auth Scope with the specified Id was found." );
                    return;
                }

                authScope = new AuthScope { Id = 0 };
            }

            hfRestUserId.Value = authScope.Id.ToString();

            if ( !isNew )
            {
                tbName.Text = authScope.Name;
                tbPublicName.Text = authScope.PublicName;
                cbActive.Checked = authScope.IsActive;
                cbIsSystem.Checked = authScope.IsSystem;

                if ( authScope.IsSystem )
                {
                    tbName.Enabled = false;
                }
            }

            var editAllowed = authScope.IsAuthorized( Authorization.EDIT, CurrentPerson );
            lbSave.Visible = editAllowed;
        }

        #endregion
    }
}