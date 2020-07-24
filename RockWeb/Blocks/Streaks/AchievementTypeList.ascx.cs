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
using System.ComponentModel;
using System.Linq;
using System.Web.UI;
using Rock.Attribute;

using Rock;
using Rock.Data;
using Rock.Model;
using Rock.Web.UI;
using Rock.Web.UI.Controls;
using Rock.Security;
using System.Collections.Generic;
using Rock.Web.Cache;
using Rock.Achievement;

namespace RockWeb.Blocks.Streaks
{
    [DisplayName( "Achievement Type List" )]
    [Category( "Streaks" )]
    [Description( "Shows a list of all achievement types." )]

    [LinkedPage(
        name: "Detail Page",
        key: AttributeKey.DetailPage )]

    public partial class AchievementTypeList : RockBlock, ICustomGridColumns
    {
        #region Keys

        /// <summary>
        /// Attribute Keys
        /// </summary>
        private static class AttributeKey
        {
            /// <summary>
            /// The detail page
            /// </summary>
            public const string DetailPage = "DetailPage";
        }

        /// <summary>
        /// Page Param Keys
        /// </summary>
        private static class PageParamKey
        {
            /// <summary>
            /// The streak type achievement type identifier
            /// </summary>
            public const string AchievementTypeId = "AchievementTypeId";

            /// <summary>
            /// The streak type identifier
            /// </summary>
            public const string StreakTypeId = "StreakTypeId";
        }

        #endregion Keys

        #region Base Control Methods

        /// <summary>
        /// Raises the <see cref="E:System.Web.UI.Control.Init" /> event.
        /// </summary>
        /// <param name="e">An <see cref="T:System.EventArgs" /> object that contains the event data.</param>
        protected override void OnInit( EventArgs e )
        {
            base.OnInit( e );

            SetTitlePrefix();

            gAchievements.DataKeyNames = new string[] { "Id" };
            gAchievements.Actions.ShowAdd = !GetAttributeValue( AttributeKey.DetailPage ).IsNullOrWhiteSpace();
            gAchievements.Actions.AddClick += gAchievements_Add;
            gAchievements.GridRebind += gAchievements_GridRebind;
            gAchievements.RowItemText = "Achievement Type";

            // Block Security and special attributes (RockPage takes care of View)
            bool canAddEditDelete = IsUserAuthorized( Authorization.EDIT );
            gAchievements.Actions.ShowAdd = canAddEditDelete;
            gAchievements.IsDeleteEnabled = canAddEditDelete;
        }


        /// <summary>
        /// Raises the <see cref="E:System.Web.UI.Control.Load" /> event.
        /// </summary>
        /// <param name="e">The <see cref="T:System.EventArgs" /> object that contains the event data.</param>
        protected override void OnLoad( EventArgs e )
        {
            if ( !Page.IsPostBack )
            {
                BindGrid();
            }

            base.OnLoad( e );
        }

        #endregion

        #region Grid Events (main grid)

        /// <summary>
        /// Handles the Add event of the gAchievements control.
        /// </summary>
        /// <param name="sender">The source of the event.</param>
        /// <param name="e">The <see cref="EventArgs" /> instance containing the event data.</param>
        protected void gAchievements_Add( object sender, EventArgs e )
        {
            NavigateToLinkedPage( AttributeKey.DetailPage, new Dictionary<string, string> {
                { PageParamKey.AchievementTypeId, default(int).ToString() },
                { PageParamKey.StreakTypeId, PageParameter( PageParamKey.StreakTypeId ) }
            } );
        }

        /// <summary>
        /// Handles the Edit event of the gAchievements control.
        /// </summary>
        /// <param name="sender">The source of the event.</param>
        /// <param name="e">The <see cref="RowEventArgs" /> instance containing the event data.</param>
        protected void gAchievements_Edit( object sender, RowEventArgs e )
        {
            NavigateToLinkedPage( AttributeKey.DetailPage, PageParamKey.AchievementTypeId, e.RowKeyId );
        }

        /// <summary>
        /// Handles the Delete event of the gAchievements control.
        /// </summary>
        /// <param name="sender">The source of the event.</param>
        /// <param name="e">The <see cref="RowEventArgs" /> instance containing the event data.</param>
        protected void gAchievements_Delete( object sender, RowEventArgs e )
        {
            var rockContext = new RockContext();
            var achievementTypeService = new AchievementTypeService( rockContext );
            var achievementType = achievementTypeService.Get( e.RowKeyId );

            if ( achievementType != null )
            {
                string errorMessage;

                if ( !achievementTypeService.CanDelete( achievementType, out errorMessage ) )
                {
                    mdGridWarning.Show( errorMessage, ModalAlertType.Information );
                    return;
                }

                achievementTypeService.Delete( achievementType );
                rockContext.SaveChanges();
            }

            BindGrid();
        }

        /// <summary>
        /// Handles the GridRebind event of the gAchievements control.
        /// </summary>
        /// <param name="sender">The source of the event.</param>
        /// <param name="e">The <see cref="EventArgs" /> instance containing the event data.</param>
        private void gAchievements_GridRebind( object sender, EventArgs e )
        {
            BindGrid();
        }

        #endregion

        #region Internal Methods

        /// <summary>
        /// Binds the grid.
        /// </summary>
        private void BindGrid()
        {
            gAchievements.DataSource = GetGridViewModels();
            gAchievements.DataBind();

            var streakTypeId = PageParameter( PageParamKey.StreakTypeId ).AsIntegerOrNull();

            if ( streakTypeId.HasValue )
            {
                var streakTypeNameCol = gAchievements.ColumnsOfType<RockBoundField>().FirstOrDefault( rbf => rbf.DataField == "StreakTypeName" );

                if ( streakTypeNameCol != null )
                {
                    streakTypeNameCol.Visible = false;
                }
            }
        }

        /// <summary>
        /// Gets the achievement types.
        /// </summary>
        /// <returns></returns>
        private List<AchievementTypeCache> GetAchievementTypes()
        {
            var streakTypeId = PageParameter( PageParamKey.StreakTypeId ).AsIntegerOrNull();

            return AchievementTypeCache.All()
                .Where( stat => !streakTypeId.HasValue || stat.StreakTypeId == streakTypeId.Value )
                .OrderBy( stat => stat.Id )
                .ToList();
        }

        /// <summary>
        /// Gets the grid view models.
        /// </summary>
        /// <param name="rockContext">The rock context.</param>
        /// <returns></returns>
        private List<AchievementTypeViewModel> GetGridViewModels()
        {
            return GetAchievementTypes().Select( at => new AchievementTypeViewModel
            {
                Id = at.Id,
                ComponentName = GetComponentName( at ),
                IconCssClass = at.AchievementIconCssClass,
                SourceName = GetSourceName( at ),
                Name = at.Name,
                IsActive = at.IsActive
            } ).ToList();
        }

        /// <summary>
        /// Gets the name of the component.
        /// </summary>
        /// <param name="achievementTypeCache">The achievement type cache.</param>
        /// <returns></returns>
        private string GetComponentName( AchievementTypeCache achievementTypeCache )
        {
            return AchievementContainer.GetComponentName( achievementTypeCache.AchievementEntityType.Name );
        }

        /// <summary>
        /// Gets the name of the source.
        /// </summary>
        /// <param name="achievementTypeCache">The achievement type cache.</param>
        /// <returns></returns>
        private string GetSourceName( AchievementTypeCache achievementTypeCache )
        {
            var interactionComponentCache = achievementTypeCache.InteractionComponentCache;

            if ( interactionComponentCache != null )
            {
                return interactionComponentCache.Name;
            }

            var streakTypeCache = achievementTypeCache.StreakTypeCache;

            if ( streakTypeCache != null )
            {
                return streakTypeCache.Name;
            }

            var sourceEntityTypeCache = achievementTypeCache.SourceEntityTypeCache;

            if ( sourceEntityTypeCache != null )
            {
                return string.Format( "Any {0}", sourceEntityTypeCache.FriendlyName );
            }

            return string.Empty;
        }

        /// <summary>
        /// Gets the achievement types.
        /// </summary>
        /// <returns></returns>
        private void SetTitlePrefix()
        {
            var streakTypeId = PageParameter( PageParamKey.StreakTypeId ).AsIntegerOrNull();
            var streakTypeCache = StreakTypeCache.Get( streakTypeId ?? 0 );
            lTitlePrefix.Text = streakTypeCache == null ? string.Empty : streakTypeCache.Name;
        }

        #endregion

        #region View Models

        /// <summary>
        /// View model for the grid line item
        /// </summary>
        private class AchievementTypeViewModel
        {
            /// <summary>
            /// Gets or sets the identifier.
            /// </summary>
            public int Id { get; set; }

            /// <summary>
            /// Gets or sets the name.
            /// </summary>
            public string Name { get; set; }

            /// <summary>
            /// Gets or sets a value indicating whether this instance is active.
            /// </summary>
            public bool IsActive { get; set; }

            /// <summary>
            /// Gets or sets the name of the source.
            /// </summary>
            public string SourceName { get; set; }

            /// <summary>
            /// Gets or sets the icon CSS class.
            /// </summary>
            public string IconCssClass { get; set; }

            /// <summary>
            /// Gets or sets the name of the component.
            /// </summary>
            public string ComponentName { get; set; }
        }

        #endregion View Models
    }
}