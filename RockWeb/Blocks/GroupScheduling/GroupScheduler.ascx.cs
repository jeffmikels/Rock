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
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data.Entity;
using System.IO;
using System.Linq;
using System.Text;
using System.Web.UI;
using System.Web.UI.WebControls;

using Rock;
using Rock.Attribute;
using Rock.Data;
using Rock.Model;
using Rock.Security;
using Rock.Web.Cache;
using Rock.Web.UI;
using Rock.Web.UI.Controls;

namespace RockWeb.Blocks.GroupScheduling
{
    /// <summary>
    ///
    /// </summary>
    [DisplayName( "Group Scheduler" )]
    [Category( "Group Scheduling" )]
    [Description( "Allows group schedules for groups and locations to be managed by a scheduler." )]

    [IntegerField(
        "Number of Weeks To Show",
        Description = "The number of weeks out that can scheduled.",
        IsRequired = true,
        DefaultIntegerValue = 6,
        Order = 0,
        Key = AttributeKey.FutureWeeksToShow )]
    public partial class GroupScheduler : RockBlock
    {
        /// <summary>
        ///
        /// </summary>
        protected class AttributeKey
        {
            /// <summary>
            /// The future weeks to show
            /// </summary>
            public const string FutureWeeksToShow = "FutureWeeksToShow";
        }

        #region PageParameterKeys

        /// <summary>
        ///
        /// </summary>
        private static class PageParameterKey
        {
            public const string GroupId = "GroupId";
            public const string GroupIds = "GroupIds";
            public const string ShowChildGroups = "ShowChildGroups";
            public const string SelectedDate = "SelectedDate";
            public const string SelectAllSchedules = "SelectAllSchedules";
            public const string IndividualScheduleId = "ScheduleId";
            public const string LocationIds = "LocationIds";
            public const string ResourceListSourceType = "ResourceListSourceType";
            public const string GroupMemberFilterType = "GroupMemberFilterType";
            public const string AlternateGroupId = "AlternateGroupId";
            public const string DataViewId = "DataViewId";
        }

        #endregion PageParameterKeys

        #region UserPreferenceKeys

        private static class UserPreferenceKey
        {
            // the selected group Id (the active group column)
            public const string SelectedGroupId = "SelectedGroupId";

            // the GroupIds that are selected in the GroupPicker
            public const string PickedGroupIds = "PickedGroupIds";

            // the value of the ShowChildGroups checkbox
            public const string ShowChildGroups = "ShowChildGroups";

            public const string SelectedDate = "SelectedDate";
            public const string SelectAllSchedules = "SelectAllSchedules";
            public const string SelectedIndividualScheduleId = "SelectedIndividualScheduleId";
            public const string SelectedLocationIds = "SelectedLocationIds";
            public const string SelectedResourceListSourceType = "SelectedResourceListSourceType";
            public const string GroupMemberFilterType = "GroupMemberFilterType";
            public const string AlternateGroupId = "AlternateGroupId";
            public const string DataViewId = "DataViewId";
        }

        #endregion UserPreferenceKeys

        #region Base Control Methods

        /// <summary>
        /// Raises the <see cref="E:System.Web.UI.Control.Init" /> event.
        /// </summary>
        /// <param name="e">An <see cref="T:System.EventArgs" /> object that contains the event data.</param>
        protected override void OnInit( EventArgs e )
        {
            base.OnInit( e );

            RockPage.AddScriptLink( "~/Scripts/dragula.min.js", true );
            RockPage.AddCSSLink( "~/Themes/Rock/Styles/group-scheduler.css", true );

            this.AddConfigurationUpdateTrigger( upnlContent );

            LoadDropDowns();

            btnCopyToClipboard.Visible = true;
            RockPage.AddScriptLink( this.Page, "~/Scripts/clipboard.js/clipboard.min.js" );
            string script = string.Format(
@"new ClipboardJS('#{0}');
    $('#{0}').tooltip();
",
btnCopyToClipboard.ClientID );

            ScriptManager.RegisterStartupScript( btnCopyToClipboard, btnCopyToClipboard.GetType(), "share-copy", script, true );
        }

        /// <summary>
        /// Raises the <see cref="E:System.Web.UI.Control.Load" /> event.
        /// </summary>
        /// <param name="e">The <see cref="T:System.EventArgs" /> object that contains the event data.</param>
        protected override void OnLoad( EventArgs e )
        {
            base.OnLoad( e );

            if ( !Page.IsPostBack )
            {
                LoadFilterFromUserPreferencesOrURL();
                ApplyFilter();
            }
        }

        #endregion Base Control Methods

        #region Methods

        private List<DateTime> _listedSundayDates = null;

        /// <summary>
        /// Loads the drop downs.
        /// </summary>
        private void LoadDropDowns()
        {
            int numOfWeeks = GetAttributeValue( AttributeKey.FutureWeeksToShow ).AsIntegerOrNull() ?? 6;

            _listedSundayDates = new List<DateTime>();

            var sundayDate = RockDateTime.Now.SundayDate();
            int weekNum = 0;
            while ( weekNum < numOfWeeks )
            {
                _listedSundayDates.Add( sundayDate );
                weekNum++;
                sundayDate = sundayDate.AddDays( 7 );
            }

            rptWeekSelector.DataSource = _listedSundayDates;
            rptWeekSelector.DataBind();
        }

        /// <summary>
        /// Shows the scheduler.
        /// </summary>
        /// <param name="visible">if set to <c>true</c> [visible].</param>
        private void ShowScheduler( bool visible )
        {
            pnlScheduler.Visible = visible;
        }

        /// <summary>
        /// Updates the list of schedules for the listed groups
        /// </summary>
        private void UpdateScheduleList( List<Group> authorizedListedGroups )
        {
            if ( !authorizedListedGroups.Any() )
            {
                ShowScheduler( false );
                return;
            }

            pnlLocationFilter.Visible = false;
            pnlScheduleFilter.Visible = false;
            ShowScheduler( false );

            List<Schedule> groupSchedules = GetGroupSchedules( authorizedListedGroups );

            pnlLocationFilter.Visible = true;
            pnlScheduleFilter.Visible = true;

            ShowScheduler( true );

            // if a schedule is already selected, set it as the selected schedule (if it still exists for this group)
            var selectedScheduleId = hfSelectedScheduleId.Value.AsIntegerOrNull();

            var listedSchedules = groupSchedules.ToList();
            var hasGroupSchedules = listedSchedules.Any();

            // Add the 'All Schedules' option to the top of the schedule selector
            listedSchedules.Insert( 0, null );

            rptScheduleSelector.DataSource = listedSchedules;
            rptScheduleSelector.DataBind();
            lScheduleFilterText.Visible = true;

            if ( !hasGroupSchedules )
            {
                lScheduleFilterText.Visible = false;
            }
            else if ( selectedScheduleId.HasValue && listedSchedules.Any( s => s != null && s.Id == selectedScheduleId.Value ) )
            {
                hfSelectedScheduleId.Value = selectedScheduleId.ToString();
            }
            else
            {
                hfSelectedScheduleId.Value = "all";
            }
        }

        /// <summary>
        /// Gets the group schedules for the listed groups
        /// </summary>
        /// <param name="listedGroups">The listed groups.</param>
        /// <returns></returns>
        private static List<Schedule> GetGroupSchedules( List<Group> listedGroups )
        {
            if ( !listedGroups.Any() )
            {
                return new List<Schedule>();
            }

            RockContext rockContext = new RockContext();
            GroupLocationService groupLocationService = new GroupLocationService( rockContext );
            var listedGroupIds = listedGroups.Select( a => a.Id ).ToArray();

            var groupLocationsQuery = groupLocationService.Queryable()
                .Where( a => listedGroupIds.Contains( a.GroupId ) );

            var groupSchedules = groupLocationsQuery
                .Where( gl => gl.Location.IsActive )
                .SelectMany( gl => gl.Schedules )
                .Where( s => s.IsActive )
                .AsNoTracking()
                .ToList()
                .DistinctBy( a => a.Guid )
                .ToList();

            groupSchedules = groupSchedules.OrderByOrderAndNextScheduledDateTime();

            return groupSchedules;
        }

        /// <summary>
        /// Gets the currently selected group.
        /// </summary>
        /// <returns></returns>
        private Group GetCurrentlySelectedGroup()
        {
            var groupId = hfSelectedGroupId.Value.AsIntegerOrNull();
            var rockContext = new RockContext();
            Group group = null;
            if ( groupId.HasValue )
            {
                group = new GroupService( rockContext ).GetNoTracking( groupId.Value );
            }

            return group;
        }

        /// <summary>
        /// Gets the authorized listed groups
        /// </summary>
        /// <returns></returns>
        private List<Group> GetAuthorizedListedGroups()
        {
            List<Group> listedGroups = GetListedGroups();

            var authorizedGroups = listedGroups.Where( g =>
            {
                var isAuthorized = g.IsAuthorized( Authorization.EDIT, this.CurrentPerson ) || g.IsAuthorized( Authorization.SCHEDULE, this.CurrentPerson );
                return isAuthorized;
            } ).ToList();

            var authorizedGroupCount = authorizedGroups.Count();
            var listedGroupCount = listedGroups.Count();

            return authorizedGroups;
        }

        /// <summary>
        /// Gets the listed groups, including ones that might not be authorized
        /// </summary>
        /// <returns></returns>
        private List<Group> GetListedGroups()
        {
            // get the selected listed groups (not including ones determined from IncludeChildGroups)
            var pickedGroupIds = gpPickedGroups.SelectedIds;

            var rockContext = new RockContext();
            var groupService = new GroupService( rockContext );

            // if the ShowChildGroups option is enabled, also include those
            List<int> childGroupIds = new List<int>();
            if ( btnShowChildGroups.Attributes["show-child-groups"].AsBoolean() )
            {
                childGroupIds = groupService.Queryable()
                    .Where( a =>
                        a.IsActive &&
                        a.ParentGroupId.HasValue &&
                        pickedGroupIds.Contains( a.ParentGroupId.Value ) )
                    .Select( a => a.Id ).ToList();
            }

            List<int> groupIdsToQuery = pickedGroupIds.Union( childGroupIds ).ToList();

            // Include ParentGroup and GroupLocations so that these don't need to get lazy loaded
            var listedGroups = groupService
                .GetByIds( groupIdsToQuery )
                .Include( a => a.ParentGroup )
                .Include( a => a.GroupLocations )
                .AsNoTracking().ToList();

            return listedGroups;
        }

        /// <summary>
        /// Loads the filter from user preferences or the URL
        /// </summary>
        private void LoadFilterFromUserPreferencesOrURL()
        {
            DateTime selectedSundayDate = this.GetUrlSettingOrBlockUserPreference( PageParameterKey.SelectedDate, UserPreferenceKey.SelectedDate ).AsDateTime() ?? RockDateTime.Now.SundayDate();
            if ( _listedSundayDates != null && _listedSundayDates.Contains( selectedSundayDate ) )
            {
                hfWeekSundayDate.Value = selectedSundayDate.ToISO8601DateString();
            }
            else
            {
                hfWeekSundayDate.Value = RockDateTime.Now.SundayDate().ToISO8601DateString();
            }

            // if there is a 'GroupIds' parameter/userpreference, that defines what groups are shown.
            // However, only one group can be selected/active at a time
            List<int> pickedGroupIds =
                ( GetUrlSettingOrBlockUserPreference( PageParameterKey.GroupIds, UserPreferenceKey.PickedGroupIds ) ?? string.Empty ).Split( ',' ).AsIntegerList();

            // if there is a 'GroupId' parameter that will define active/selected group
            int? selectedGroupId = GetUrlSettingOrBlockUserPreference( PageParameterKey.GroupId, UserPreferenceKey.SelectedGroupId ).AsIntegerOrNull();

            if ( !selectedGroupId.HasValue && pickedGroupIds.Any() )
            {
                // if there isn't a specific group specified, default to the first one that has scheduling enabled
                int firstScheduleEnabledGroupId = GetSchedulingEnabledGroupIds( pickedGroupIds ).FirstOrDefault();

                selectedGroupId = firstScheduleEnabledGroupId;
            }

            if ( selectedGroupId.HasValue )
            {
                // if there is a GroupId specified, but it isn't in the listed groups, add it to the list
                if ( !pickedGroupIds.Contains( selectedGroupId.Value ) )
                {
                    pickedGroupIds.Add( selectedGroupId.Value );
                }
            }

            bool showChildGroups = GetUrlSettingOrBlockUserPreference( PageParameterKey.ShowChildGroups, UserPreferenceKey.ShowChildGroups ).AsBooleanOrNull() ?? false;

            gpPickedGroups.SetValues( pickedGroupIds );
            SetStateForShowChildGroupsButton( showChildGroups );


            if ( this.PageParameter( PageParameterKey.GroupIds ).IsNotNullOrWhiteSpace() )
            {
                // disable the groups picker if groupId(s) are specified in the URL
                gpPickedGroups.Enabled = false;
                btnShowChildGroups.Enabled = false;
            }

            hfSelectedGroupId.Value = selectedGroupId.ToString();

            var authorizedListedGroups = GetAuthorizedListedGroups();

            UpdateScheduleList( authorizedListedGroups );
            bool selectAllSchedules = this.GetUrlSettingOrBlockUserPreference( PageParameterKey.SelectAllSchedules, UserPreferenceKey.SelectAllSchedules ).AsBoolean();
            int? selectedIndividualScheduleId = this.GetUrlSettingOrBlockUserPreference( PageParameterKey.IndividualScheduleId, UserPreferenceKey.SelectedIndividualScheduleId ).AsIntegerOrNull();

            if ( selectAllSchedules )
            {
                hfSelectedScheduleId.Value = "all";
            }
            else
            {
                hfSelectedScheduleId.Value = selectedIndividualScheduleId.ToString();
            }

            UpdateLocationList( authorizedListedGroups );
            hfSelectedLocationIds.Value = this.GetUrlSettingOrBlockUserPreference( PageParameterKey.LocationIds, UserPreferenceKey.SelectedLocationIds );

            var resourceListSourceType = this.GetUrlSettingOrBlockUserPreference( PageParameterKey.ResourceListSourceType, UserPreferenceKey.SelectedResourceListSourceType ).ConvertToEnumOrNull<SchedulerResourceListSourceType>() ?? SchedulerResourceListSourceType.GroupMembers;
            var groupMemberFilterType = this.GetUrlSettingOrBlockUserPreference( PageParameterKey.GroupMemberFilterType, UserPreferenceKey.GroupMemberFilterType ).ConvertToEnumOrNull<SchedulerResourceGroupMemberFilterType>() ?? SchedulerResourceGroupMemberFilterType.ShowAllGroupMembers;

            SetResourceListSourceType( resourceListSourceType, groupMemberFilterType );

            gpResourceListAlternateGroup.SetValue( this.GetUrlSettingOrBlockUserPreference( PageParameterKey.AlternateGroupId, UserPreferenceKey.AlternateGroupId ).AsIntegerOrNull() );
            dvpResourceListDataView.SetValue( this.GetUrlSettingOrBlockUserPreference( PageParameterKey.DataViewId, UserPreferenceKey.DataViewId ).AsIntegerOrNull() );
        }

        /// <summary>
        /// Sets the state of the ShowChildGroups button.
        /// </summary>
        /// <param name="showChildGroups">if set to <c>true</c> [show child groups].</param>
        private void SetStateForShowChildGroupsButton( bool showChildGroups )
        {
            btnShowChildGroups.Attributes["show-child-groups"] = showChildGroups.ToJavaScriptValue();
            if ( showChildGroups )
            {
                btnShowChildGroups.Text = "<i class='fa fa-check-square'></i> Show Child Groups";
            }
            else
            {
                btnShowChildGroups.Text = "<i class='fa fa-square-o'></i> Show Child Groups";
            }
        }

        /// <summary>
        /// Gets the scheduling enabled group ids.
        /// </summary>
        /// <param name="authorizedGroupIds">The authorized group ids.</param>
        /// <returns></returns>
        private static int[] GetSchedulingEnabledGroupIds( List<int> authorizedGroupIds )
        {
            var schedulingEnabledGroupIds =
             new GroupService( new RockContext() )
                .GetByIds( authorizedGroupIds )
                .Where( a => a.GroupType.IsSchedulingEnabled && !a.DisableScheduling )
                .Select( a => a.Id )
                .ToArray();

            return schedulingEnabledGroupIds;
        }

        /// <summary>
        /// Gets the URL setting (if there is one) or block user preference.
        /// </summary>
        /// <param name="key">The key.</param>
        /// <returns></returns>
        private string GetUrlSettingOrBlockUserPreference( string pageParameterKey, string userPreferenceKey )
        {
            string setting = Request.QueryString[pageParameterKey];
            if ( setting != null )
            {
                return setting;
            }

            return this.GetBlockUserPreference( userPreferenceKey );
        }

        /// <summary>
        /// Saves the user preferences and updates the resource list and locations based on the filter
        /// </summary>
        private void ApplyFilter()
        {
            var authorizedListedGroups = this.GetAuthorizedListedGroups();

            List<int> listedGroupIds = authorizedListedGroups.Select( a => a.Id ).ToList();

            int? selectedGroupId = null;
            var selectedGroup = this.GetCurrentlySelectedGroup();
            if ( selectedGroup != null )
            {
                selectedGroupId = selectedGroup.Id;
            }

            List<int> scheduleIds = GetSelectedScheduleIds( authorizedListedGroups );

            var sundayDate = hfWeekSundayDate.Value.AsDateTime() ?? RockDateTime.Now.SundayDate();

            lWeekFilterText.Text = string.Format( "<i class='fa fa-calendar-alt'></i> Week: {0}", sundayDate.ToShortDateString() );

            this.SetBlockUserPreference( UserPreferenceKey.SelectedGroupId, selectedGroupId.ToString(), false );
            this.SetBlockUserPreference( UserPreferenceKey.PickedGroupIds, gpPickedGroups.SelectedIds.ToList().AsDelimited( "," ), false );
            this.SetBlockUserPreference( UserPreferenceKey.ShowChildGroups, btnShowChildGroups.Attributes["show-child-groups"], false );

            this.SetBlockUserPreference( UserPreferenceKey.SelectedDate, sundayDate.ToISO8601DateString(), false );

            this.SetBlockUserPreference( UserPreferenceKey.SelectedLocationIds, hfSelectedLocationIds.Value, false );
            bool selectAllSchedules = hfSelectedScheduleId.Value.AsIntegerOrNull() == null;
            int? selectedScheduleId = hfSelectedScheduleId.Value.AsIntegerOrNull();
            this.SetBlockUserPreference( UserPreferenceKey.SelectAllSchedules, selectAllSchedules.ToString(), false );
            this.SetBlockUserPreference( UserPreferenceKey.SelectedIndividualScheduleId, selectedScheduleId.ToString(), false );
            this.SaveBlockUserPreferences();

            var rockContext = new RockContext();

            Schedule selectedSchedule = null;
            if ( selectedScheduleId.HasValue )
            {
                selectedSchedule = new ScheduleService( rockContext ).GetNoTracking( selectedScheduleId.Value );
            }

            string selectedSchedulesText;

            if ( selectAllSchedules || selectedSchedule == null )
            {
                selectedSchedulesText = "All Schedules";
            }
            else
            {
                if ( selectedSchedule.Name.IsNotNullOrWhiteSpace() )
                {
                    selectedSchedulesText = selectedSchedule.Name;
                }
                else
                {
                    selectedSchedulesText = selectedSchedule.ToFriendlyScheduleText();
                }
            }

            lScheduleFilterText.Text = string.Format( "<i class='fa fa-clock-o'></i>  {0}", selectedSchedulesText );

            var resourceListSourceType = ( SchedulerResourceListSourceType ) hfSchedulerResourceListSourceType.Value.AsInteger();
            var groupMemberFilterType = ( SchedulerResourceGroupMemberFilterType ) hfResourceGroupMemberFilterType.Value.AsInteger();

            List<SchedulerResourceListSourceType> schedulerResourceListSourceTypes = Enum.GetValues( typeof( SchedulerResourceListSourceType ) ).OfType<SchedulerResourceListSourceType>().ToList();

            if ( selectedGroup != null && selectedGroup.SchedulingMustMeetRequirements )
            {
                var sameGroupSourceTypes = new SchedulerResourceListSourceType[] { SchedulerResourceListSourceType.GroupMembers, SchedulerResourceListSourceType.GroupMatchingPreference };

                // don't show options for other groups or people if SchedulingMustMeetRequirements
                // this is because people from other groups wouldn't meet scheduling requirements (since they aren't in the same group as the Attendance Occurrence)
                schedulerResourceListSourceTypes = sameGroupSourceTypes.ToList();

                if ( !sameGroupSourceTypes.Contains( resourceListSourceType ) )
                {
                    resourceListSourceType = SchedulerResourceListSourceType.GroupMembers;
                    SetResourceListSourceType( resourceListSourceType, groupMemberFilterType );
                }
            }
            else
            {
                if ( selectedGroup == null || !selectedGroup.ParentGroupId.HasValue )
                {
                    schedulerResourceListSourceTypes = schedulerResourceListSourceTypes.Where( a => a != SchedulerResourceListSourceType.ParentGroup ).ToList();
                }

                pnlAddPerson.Visible = true;
                ppAddPerson.Visible = true;
            }

            rptSchedulerResourceListSourceType.DataSource = schedulerResourceListSourceTypes;
            rptSchedulerResourceListSourceType.DataBind();

            this.SetBlockUserPreference( UserPreferenceKey.SelectedResourceListSourceType, resourceListSourceType.ToString(), false );
            this.SetBlockUserPreference( UserPreferenceKey.GroupMemberFilterType, groupMemberFilterType.ToString(), false );
            this.SetBlockUserPreference( UserPreferenceKey.AlternateGroupId, gpResourceListAlternateGroup.SelectedValue, false );
            this.SetBlockUserPreference( UserPreferenceKey.DataViewId, dvpResourceListDataView.SelectedValue, false );
            this.SaveBlockUserPreferences();

            pnlResourceFilterAlternateGroup.Visible = resourceListSourceType == SchedulerResourceListSourceType.AlternateGroup;
            pnlResourceFilterDataView.Visible = resourceListSourceType == SchedulerResourceListSourceType.DataView;

            var listedLocations = GetListedLocations( authorizedListedGroups, scheduleIds );
            var selectedLocationIds = hfSelectedLocationIds.Value.Split( ',' ).AsIntegerList();

            // fix up the list of selectedGroupLocationIds to only include ones that are listed
            selectedLocationIds = selectedLocationIds.Where( a => listedLocations.Any( l => l.Id == a ) ).ToList();
            hfSelectedLocationIds.Value = selectedLocationIds.AsDelimited( "," );

            List<Location> selectedLocations = new LocationService( rockContext )
                .GetByIds( selectedLocationIds )
                .OrderBy( a => a.Name )
                .AsNoTracking()
                .ToList();

            bool selectAllLocations = false;

            string selectedLocationFilterText;

            // if no locations are selected(because 'all' was selected), or if all the listed locations are selected, then all locations will be selected
            var allLocationsSelected = !selectedLocations.Any() || listedLocations.All( sl => selectedLocations.Any( ll => ll.Id == sl.Id ) );

            if ( allLocationsSelected )
            {
                selectedLocationFilterText = "All Locations";
                selectedLocationIds = listedLocations.Where( a => a != null ).Select( a => a.Id ).ToList();
                hfSelectedLocationIds.Value = selectedLocationIds.AsDelimited( "," );
                selectAllLocations = true;
            }
            else if ( selectedLocations.Count() == 1 )
            {
                selectedLocationFilterText = selectedLocations.First().ToString();
            }
            else
            {
                selectedLocationFilterText = string.Format(
                    "<span title='{0}'>{1} Locations</span>",
                    selectedLocations.Select( a => a.ToString() ).ToList().AsDelimited( ", " ).EncodeHtml(),
                    selectedLocations.Count() );
            }

            lSelectedLocationFilterText.Text = string.Format( "<i class='fa fa-building'></i> {0}", selectedLocationFilterText );

            var locationButtons = rptLocationSelector.ControlsOfTypeRecursive<LinkButton>().ToList();
            var locationService = new LocationService( rockContext );
            foreach ( var locationButton in locationButtons )
            {
                var locationId = locationButton.CommandArgument.AsIntegerOrNull();
                if ( locationId.HasValue )
                {
                    var location = listedLocations.Where( a => a != null ).Where( a => a.Id == locationId.Value ).FirstOrDefault();
                    if ( location != null )
                    {
                        if ( selectedLocationIds.Contains( locationId.Value ) )
                        {
                            locationButton.Text = string.Format( "<i class='fa fa-check'></i> {0}", location.ToString().EncodeHtml() );
                        }
                        else
                        {
                            locationButton.Text = string.Format( " {0}", location.ToString() );
                        }
                    }
                }
                else
                {
                    // all locations button
                    if ( selectAllLocations )
                    {
                        locationButton.Text = "<i class='fa fa-check'></i> All Locations";
                    }
                    else
                    {
                        locationButton.Text = " All Locations";
                    }
                }
            }

            bool filterIsValid = ValidateFilter( authorizedListedGroups, selectedGroup, scheduleIds, listedLocations, selectedLocationIds );

            ShowScheduler( filterIsValid );

            pnlLocationFilter.Visible = authorizedListedGroups.Any();
            pnlScheduleFilter.Visible = authorizedListedGroups.Any();

            if ( filterIsValid )
            {
                InitResourceList( authorizedListedGroups );
                BindAttendanceOccurrences( authorizedListedGroups );
            }

            // Create URL for selected settings
            var pageReference = CurrentPageReference;
            foreach ( var setting in GetBlockUserPreferences() )
            {
                pageReference.Parameters.AddOrReplace( setting.Key, setting.Value );
            }

            Uri uri = new Uri( Request.Url.ToString() );
            btnCopyToClipboard.Attributes["data-clipboard-text"] = uri.GetLeftPart( UriPartial.Authority ) + pageReference.BuildUrl();
            btnCopyToClipboard.Disabled = false;
        }

        /// <summary>
        /// Validates the filter and shows filter warnings if the filter is not valid
        /// </summary>
        /// <param name="authorizedListedGroups">The authorized listed groups.</param>
        /// <param name="selectedGroup">The selected group.</param>
        /// <param name="scheduleIds">The schedule ids.</param>
        /// <param name="listedLocations">The listed locations.</param>
        /// <param name="selectedGroupLocationIds">The selected group location ids.</param>
        /// <returns></returns>
        private bool ValidateFilter( List<Group> authorizedListedGroups, Group selectedGroup, List<int> scheduleIds, List<Location> listedLocations, List<int> selectedLocationIds )
        {
            bool filterIsValid = false;

            var pickedGroupCount = gpPickedGroups.SelectedIds.Count();

            var hasMultipleGroupsSelected = authorizedListedGroups.Count() > 1;
            var authorizedGroupsWarning = string.Empty;

            if ( pickedGroupCount > 0 && authorizedListedGroups.Count == 0 )
            {
                if ( hasMultipleGroupsSelected )
                {
                    authorizedGroupsWarning = "You're not authorized to schedule resources for these groups";
                }
                else
                {
                    authorizedGroupsWarning = "You're not authorized to schedule resources for this group";
                }
            }
            else if ( pickedGroupCount > 0 && authorizedListedGroups.Count < pickedGroupCount )
            {
                authorizedGroupsWarning = "You're not authorized to schedule resources for some of these groups";
            }

            nbAuthorizedGroupsWarning.Visible = authorizedGroupsWarning.IsNotNullOrWhiteSpace();
            nbAuthorizedGroupsWarning.Text = authorizedGroupsWarning;

            string filterMessage;
            NotificationBoxType filterNotificationBoxType = NotificationBoxType.Warning;
            if ( pickedGroupCount == 0 )
            {
                filterMessage = "Please select as least one group";
                filterNotificationBoxType = NotificationBoxType.Info;
            }
            else if ( !listedLocations.Any() )
            {
                if ( hasMultipleGroupsSelected )
                {
                    filterMessage = "The selected groups do not have any locations";
                }
                else
                {
                    filterMessage = "The selected group does not have any locations";
                }
            }
            else if ( !selectedLocationIds.Any() )
            {
                filterMessage = "Please select as least one location";
                filterNotificationBoxType = NotificationBoxType.Info;
            }
            else if ( !scheduleIds.Any() )
            {
                if ( hasMultipleGroupsSelected )
                {
                    filterMessage = "The selected groups do not have any schedules";
                }
                else
                {
                    filterMessage = "The selected group does not have any schedules";
                }
            }
            else
            {
                filterMessage = string.Empty;
                filterIsValid = true;
            }

            var schedulingDisabledForSelectedGroup = selectedGroup != null && selectedGroup.DisableScheduling;
            nbSchedulingDisabledWarning.Visible = schedulingDisabledForSelectedGroup;
            if ( schedulingDisabledForSelectedGroup )
            {
                nbSchedulingDisabledWarning.Text = string.Format( "Scheduling is disabled for the {0} group.", selectedGroup.Name );
            }

            nbFilterMessage.Visible = !filterIsValid;
            nbFilterMessage.Text = filterMessage;
            nbFilterMessage.NotificationBoxType = filterNotificationBoxType;
            return filterIsValid;
        }

        /// <summary>
        /// Gets the selected schedule ids.
        /// </summary>
        /// <param name="authorizedListedGroups">The authorized listed groups.</param>
        /// <returns></returns>
        private List<int> GetSelectedScheduleIds( List<Group> authorizedListedGroups )
        {
            var selectedScheduleId = hfSelectedScheduleId.Value.AsIntegerOrNull();
            if ( selectedScheduleId.HasValue )
            {
                var selectedScheduleIds = new List<int>();
                selectedScheduleIds.Add( selectedScheduleId.Value );
                return selectedScheduleIds;
            }

            var scheduleList = GetGroupSchedules( authorizedListedGroups );

            if ( scheduleList != null )
            {
                return scheduleList.Where( a => a != null ).Select( a => a.Id ).ToList();
            }
            else
            {
                return new List<int>();
            }
        }

        /// <summary>
        /// Updates the list of locations for the selected groups
        /// </summary>
        private void UpdateLocationList( List<Group> authorizedListedGroups )
        {
            if ( !authorizedListedGroups.Any() )
            {
                ShowScheduler( false );
                return;
            }

            if ( authorizedListedGroups.Any() )
            {
                ShowScheduler( true );
                List<int> scheduleIds = GetSelectedScheduleIds( authorizedListedGroups );

                var listedLocations = GetListedLocations( authorizedListedGroups, scheduleIds );

                if ( listedLocations.Any() )
                {
                    listedLocations.Insert( 0, null );
                    lSelectedLocationFilterText.Visible = true;
                }
                else
                {
                    lSelectedLocationFilterText.Visible = false;
                }

                rptLocationSelector.DataSource = listedLocations;
                rptLocationSelector.DataBind();
            }
        }

        /// <summary>
        /// Gets the listed locations.
        /// </summary>
        /// <param name="group">The group.</param>
        /// <param name="scheduleIds">The schedule ids.</param>
        /// <returns></returns>
        private List<Location> GetListedLocations( List<Group> listedGroups, List<int> scheduleIds )
        {
            var rockContext = new RockContext();
            var listedGroupIds = listedGroups.Select( a => a.Id ).ToList();

            var groupLocationsQuery = new GroupLocationService( rockContext ).Queryable()
                .Where( gl =>
                    listedGroupIds.Contains( gl.GroupId ) &&
                    gl.Schedules.Any( s => scheduleIds.Contains( s.Id ) ) &&
                    gl.Location.IsActive )
                .OrderBy( a => new { a.Order, a.Location.Name } )
                .AsNoTracking();

            var listedLocations = groupLocationsQuery.Select( a => a.Location ).ToList().DistinctBy( a => a.Id ).ToList();

            return listedLocations;
        }

        /// <summary>
        /// Set the Resource List hidden fields which groupScheduler.js uses to populate the Resource List
        /// </summary>
        private void InitResourceList( List<Group> authorizedListedGroups )
        {
            int groupId = hfSelectedGroupId.Value.AsInteger();
            int? resourceGroupId = null;
            int? resourceDataViewId = null;

            List<int> scheduleIds = GetSelectedScheduleIds( authorizedListedGroups );

            hfResourceAdditionalPersonIds.Value = string.Empty;

            var resourceListSourceType = hfSchedulerResourceListSourceType.Value.ConvertToEnum<SchedulerResourceListSourceType>();
            switch ( resourceListSourceType )
            {
                case SchedulerResourceListSourceType.GroupMembers:
                case SchedulerResourceListSourceType.GroupMatchingPreference:
                    {
                        resourceGroupId = groupId;
                        break;
                    }

                case SchedulerResourceListSourceType.AlternateGroup:
                    {
                        resourceGroupId = gpResourceListAlternateGroup.SelectedValue.AsInteger();
                        break;
                    }

                case SchedulerResourceListSourceType.ParentGroup:
                    {
                        var rockContext = new RockContext();
                        resourceGroupId = new GroupService( rockContext ).GetSelect( groupId, s => s.ParentGroupId );
                        break;
                    }

                case SchedulerResourceListSourceType.DataView:
                    {
                        resourceDataViewId = dvpResourceListDataView.SelectedValue.AsInteger();
                        break;
                    }
            }

            hfOccurrenceGroupId.Value = groupId.ToString();
            hfOccurrenceScheduleIds.Value = scheduleIds.AsDelimited( "," );
            hfOccurrenceSundayDate.Value = ( hfWeekSundayDate.Value.AsDateTime() ?? RockDateTime.Now.SundayDate() ).ToISO8601DateString();

            hfResourceGroupId.Value = resourceGroupId.ToString();
            hfResourceDataViewId.Value = resourceDataViewId.ToString();
            hfResourceAdditionalPersonIds.Value = string.Empty;
        }

        /// <summary>
        /// Binds the Attendance Occurrences ( Which shows the Location for the Attendance Occurrence for the selected Group + DateTime + Location ).
        /// groupScheduler.js will populate these with the scheduled resources
        /// </summary>
        private void BindAttendanceOccurrences( List<Group> authorizedListedGroups )
        {
            var occurrenceSundayDate = hfOccurrenceSundayDate.Value.AsDateTime().Value.Date;
            var occurrenceSundayWeekStartDate = occurrenceSundayDate.AddDays( -6 );

            // make sure we don't let them schedule dates in the past
            if ( occurrenceSundayWeekStartDate <= RockDateTime.Today )
            {
                occurrenceSundayWeekStartDate = RockDateTime.Today;
            }

            var scheduleIds = GetSelectedScheduleIds( authorizedListedGroups );

            var rockContext = new RockContext();

            var occurrenceSchedules = new ScheduleService( rockContext ).GetByIds( scheduleIds ).AsNoTracking().ToList();

            if ( !occurrenceSchedules.Any() )
            {
                btnAutoSchedule.Visible = false;
                return;
            }

            btnAutoSchedule.Visible = true;

            var attendanceOccurrenceService = new AttendanceOccurrenceService( rockContext );
            var selectedLocationIds = hfSelectedLocationIds.Value.Split( ',' ).AsIntegerList();

            var groupIds = authorizedListedGroups.Select( a => a.Id ).ToList();

            var selectedGroupLocationIds = new GroupLocationService( rockContext ).Queryable()
                .Where( a => groupIds.Contains( a.GroupId ) && selectedLocationIds.Contains( a.LocationId ) )
                .Select( a => a.Id ).ToList();

            List<DateTime> occurrenceDatesForAllSchedules = new List<DateTime>();

            foreach ( var occurrenceSchedule in occurrenceSchedules )
            {
                // get all the occurrences for the selected week for the selected schedule.
                // we only want create occurrences start times for this specific schedule
                // Note that it could be more than once a week if it is a daily scheduled, or it might not be in the selected week if it is every 2 weeks, etc
                var scheduleOccurrenceDates = occurrenceSchedule
                    .GetScheduledStartTimes( occurrenceSundayWeekStartDate, occurrenceSundayDate.AddDays( 1 ) )
                    .Select( a => a.Date )
                    .Distinct()
                    .ToList();

                List<AttendanceOccurrence> missingAttendanceOccurrenceListForSchedule =
                    attendanceOccurrenceService.CreateMissingAttendanceOccurrences( scheduleOccurrenceDates, occurrenceSchedule.Id, selectedGroupLocationIds );

                attendanceOccurrenceService.AddRange( missingAttendanceOccurrenceListForSchedule );
                rockContext.SaveChanges();

                occurrenceDatesForAllSchedules.AddRange( scheduleOccurrenceDates );
            }

            var occurrenceDateList = occurrenceDatesForAllSchedules.Select( a => a.Date ).Distinct().ToList();

            IQueryable<AttendanceOccurrenceService.AttendanceOccurrenceGroupLocationScheduleConfigJoinResult> attendanceOccurrenceGroupLocationScheduleConfigQuery
                = attendanceOccurrenceService.AttendanceOccurrenceGroupLocationScheduleConfigJoinQuery( occurrenceDateList, scheduleIds, selectedGroupLocationIds );

            OccurrenceDisplayMode occurrenceDisplayMode;
            if ( authorizedListedGroups.Count > 1 )
            {
                occurrenceDisplayMode = OccurrenceDisplayMode.MultiGroup;
            }
            else
            {
                occurrenceDisplayMode = OccurrenceDisplayMode.ScheduleOccurrenceDate;
            }

            var attendanceOccurrencesList = attendanceOccurrenceGroupLocationScheduleConfigQuery.AsNoTracking()
                .OrderBy( a => a.GroupLocation.Order ).ThenBy( a => a.GroupLocation.Location.Name )
                .Select( a => new AttendanceOccurrenceRowItem
                {
                    OccurrenceDisplayMode = occurrenceDisplayMode,
                    LocationName = a.AttendanceOccurrence.Location.Name,
                    GroupLocationOrder = a.GroupLocation.Order,
                    LocationId = a.AttendanceOccurrence.LocationId,
                    Group = a.AttendanceOccurrence.Group,
                    Schedule = a.AttendanceOccurrence.Schedule,
                    OccurrenceDate = a.AttendanceOccurrence.OccurrenceDate,
                    AttendanceOccurrenceId = a.AttendanceOccurrence.Id,
                    CapacityInfo = new CapacityInfo
                    {
                        MinimumCapacity = a.GroupLocationScheduleConfig.MinimumCapacity,
                        DesiredCapacity = a.GroupLocationScheduleConfig.DesiredCapacity,
                        MaximumCapacity = a.GroupLocationScheduleConfig.MaximumCapacity
                    }
                } ).ToList();

            var selectedGroupId = hfSelectedGroupId.Value.AsInteger();

            var attendanceOccurrencesOrderedList = attendanceOccurrencesList.OrderBy( a => a.ScheduledDateTime ).ThenBy( a => a.GroupLocationOrder ).ThenBy( a => a.LocationName ).ToList();

            // if there are any people that signed up with no location preference, add the to a special list of "No Location Preference" occurrences to the top of the list
            var unassignedLocationOccurrenceList = attendanceOccurrenceService.Queryable()
                .Where( a => occurrenceDateList.Contains( a.OccurrenceDate )
                    && a.ScheduleId.HasValue
                    && scheduleIds.Contains( a.ScheduleId.Value )
                    && a.GroupId == selectedGroupId
                    && a.LocationId.HasValue == false )
                .Where( a => a.Attendees.Any( x => x.RequestedToAttend == true || x.ScheduledToAttend == true ) )
                .Select( a => new AttendanceOccurrenceRowItem
                {
                    LocationName = "No Location Preference",
                    GroupLocationOrder = 0,
                    LocationId = null,
                    Group = a.Group,
                    Schedule = a.Schedule,
                    OccurrenceDate = a.OccurrenceDate,
                    AttendanceOccurrenceId = a.Id,
                    CapacityInfo = new CapacityInfo()
                } )
                .ToList()
                .OrderBy( a => a.ScheduledDateTime )
                .ToList();

            int maxOccurrences = 250;
            if ( attendanceOccurrencesOrderedList.Count > maxOccurrences )
            {
                nbFilterMessage.Visible = true;
                nbFilterMessage.NotificationBoxType = NotificationBoxType.Warning;
                nbFilterMessage.Text = string.Format(
                    "There are {0} attendance occurrences for selected filter. Please change the filter so that less than {1} occurrences are shown.",
                    attendanceOccurrencesOrderedList.Count,
                    maxOccurrences );
                return;
            }

            attendanceOccurrencesOrderedList.InsertRange( 0, unassignedLocationOccurrenceList );

            List<OccurrenceColumnItem> occurrenceColumnDataList;

            var sundayDate = RockDateTime.Now.SundayDate();

            if ( occurrenceDisplayMode == OccurrenceDisplayMode.MultiGroup )
            {
                // sort the occurrenceColumns so the selected Group is in the first column, then order by Group.Order/Name
                occurrenceColumnDataList = attendanceOccurrencesOrderedList
                    .GroupBy( a => a.Group.Id )
                    .Select( a =>
                    {
                        // we are grouping by GroupId but we need Group.
                        // since all of these will have the same Group, we can just grab the first one
                        var group = a.Select( s => s.Group ).FirstOrDefault();

                        var item = new OccurrenceColumnItem
                        {
                            OccurrenceDisplayMode = occurrenceDisplayMode,
                            Group = group,
                            Schedule = ( Schedule ) null,
                            OccurrenceDate = ( DateTime? ) null,
                            AttendanceOccurrenceItems = a.ToList()
                        };

                        return item;
                    } )
                    .OrderBy( a => a.Group.Id == selectedGroupId ? 0 : 1 )
                    .ThenBy( a => a.Group.Order ).ThenBy( a => a.Group.Name ).ToList();
            }
            else
            {
                occurrenceColumnDataList = attendanceOccurrencesOrderedList
                    .GroupBy( a => new { ScheduleId = a.Schedule.Id, a.OccurrenceDate } )
                    .Select( a =>
                    {
                        // we are grouping by ScheduleId but we need Schedule.
                        // since all of these will have the same Schedule, we can just grab the first one
                        var schedule = a.Select( s => s.Schedule ).FirstOrDefault();

                        var item = new OccurrenceColumnItem
                        {
                            OccurrenceDisplayMode = occurrenceDisplayMode,
                            Group = null,
                            Schedule = schedule,
                            OccurrenceDate = a.Key.OccurrenceDate,
                            AttendanceOccurrenceItems = a.ToList()
                        };

                        return item;
                    } )
                    .OrderBy( a => a.OccurrenceDate )
                    .ThenBy( a => a.Schedule.Order )
                    .ThenBy( a => a.Schedule.GetNextStartDateTime( sundayDate ) )
                    .ToList();
            }

            hfDisplayedOccurrenceIds.Value = attendanceOccurrencesOrderedList.Select( a => a.AttendanceOccurrenceId ).ToList().AsDelimited( "," );
            rptOccurrenceColumns.DataSource = occurrenceColumnDataList;
            rptOccurrenceColumns.DataBind();
        }

        /// <summary>
        ///
        /// </summary>
        private class CapacityInfo
        {
            /// <summary>
            /// Gets or sets the minimum capacity.
            /// </summary>
            /// <value>
            /// The minimum capacity.
            /// </value>
            public int? MinimumCapacity { get; set; }

            /// <summary>
            /// Gets or sets the desired capacity.
            /// </summary>
            /// <value>
            /// The desired capacity.
            /// </value>
            public int? DesiredCapacity { get; set; }

            /// <summary>
            /// Gets or sets the maximum capacity.
            /// </summary>
            /// <value>
            /// The maximum capacity.
            /// </value>
            public int? MaximumCapacity { get; set; }
        }

        /// <summary>
        ///
        /// </summary>
        public enum OccurrenceDisplayMode
        {
            ScheduleOccurrenceDate,
            MultiGroup
        }

        [System.Diagnostics.DebuggerDisplay( "{Group} {Schedule} {OccurrenceDate}" )]
        private class OccurrenceColumnItem
        {
            /// <summary>
            /// Gets or sets the occurrence display mode.
            /// </summary>
            /// <value>
            /// The occurrence display mode.
            /// </value>
            public OccurrenceDisplayMode OccurrenceDisplayMode { get; set; }

            /// <summary>
            /// Gets or sets the group (when in <see cref="OccurrenceDisplayMode.MultiGroup"/> )
            /// </summary>
            /// <value>
            /// The group.
            /// </value>
            public Group Group { get; set; }

            /// <summary>
            /// Gets or sets the schedule (when in <see cref="OccurrenceDisplayMode.ScheduleOccurrenceDate"/> )
            /// </summary>
            /// <value>
            /// The schedule.
            /// </value>
            public Schedule Schedule { get; set; }

            /// <summary>
            /// Gets or sets the occurrence date (when in <see cref="OccurrenceDisplayMode.ScheduleOccurrenceDate"/> )
            /// </summary>
            /// <value>
            /// The occurrence date.
            /// </value>
            public DateTime? OccurrenceDate { get; set; }

            /// <summary>
            /// Gets the Schedule's scheduled date time the Occurrence Date  (when in <see cref="OccurrenceDisplayMode.ScheduleOccurrenceDate"/> )
            /// </summary>
            /// <value>
            /// The scheduled date time.
            /// </value>
            public DateTime? ScheduledDateTime
            {
                get
                {
                    if ( this.OccurrenceDate.HasValue )
                    {
                        return Schedule.GetNextStartDateTime( this.OccurrenceDate.Value );
                    }

                    return null;
                }
            }

            /// <summary>
            /// Gets or sets the attendance occurrence items for this column
            /// </summary>
            /// <value>
            /// The attendance occurrence items.
            /// </value>
            public List<AttendanceOccurrenceRowItem> AttendanceOccurrenceItems { get; set; }
        }

        /// <summary>
        ///
        /// </summary>
        [System.Diagnostics.DebuggerDisplay( "{Schedule} {OccurrenceDate} {ScheduledDateTime}" )]
        private class AttendanceOccurrenceRowItem
        {
            public OccurrenceDisplayMode OccurrenceDisplayMode { get; set; }

            /// <summary>
            /// Gets or sets the attendance occurrence identifier.
            /// </summary>
            /// <value>
            /// The attendance occurrence identifier.
            /// </value>
            public int AttendanceOccurrenceId { get; set; }

            /// <summary>
            /// Gets or sets the capacity information.
            /// </summary>
            /// <value>
            /// The capacity information.
            /// </value>
            public CapacityInfo CapacityInfo { get; set; }

            /// <summary>
            /// Gets or sets the name of the location.
            /// </summary>
            /// <value>
            /// The name of the location.
            /// </value>
            public string LocationName { get; set; }

            /// <summary>
            /// Gets or sets the location identifier.
            /// NOTE: There should only be one that doesn't have a LocationId, and it should only be shown if there are assignments in it
            /// </summary>
            /// <value>
            /// The location identifier.
            /// </value>
            public int? LocationId { get; set; }

            /// <summary>
            /// Gets or sets the schedule.
            /// </summary>
            /// <value>
            /// The schedule.
            /// </value>
            public Schedule Schedule { get; set; }

            /// <summary>
            /// Gets the Schedule's scheduled date time the Occurrence Date
            /// </summary>
            /// <value>
            /// The scheduled date time.
            /// </value>
            public DateTime? ScheduledDateTime
            {
                get
                {
                    return Schedule.GetNextStartDateTime( this.OccurrenceDate );
                }
            }

            public Group Group { get; set; }

            /// <summary>
            /// Gets or sets the occurrence date.
            /// </summary>
            /// <value>
            /// The occurrence date.
            /// </value>
            public DateTime OccurrenceDate { get; set; }

            /// <summary>
            /// Gets or sets the group location order.
            /// </summary>
            /// <value>
            /// The group location order.
            /// </value>
            public int GroupLocationOrder { get; internal set; }
        }

        /// <summary>
        /// Handles the ItemDataBound event of the rptOccurrenceColumns control.
        /// </summary>
        /// <param name="sender">The source of the event.</param>
        /// <param name="e">The <see cref="RepeaterItemEventArgs"/> instance containing the event data.</param>
        protected void rptOccurrenceColumns_ItemDataBound( object sender, RepeaterItemEventArgs e )
        {
            var rptAttendanceOccurrences = e.Item.FindControl( "rptAttendanceOccurrences" ) as Repeater;
            var pnlMultiGroupModeColumnHeading = e.Item.FindControl( "pnlMultiGroupModeColumnHeading" ) as Panel;
            var pnlSingleGroupModeColumnHeading = e.Item.FindControl( "pnlSingleGroupModeColumnHeading" ) as Panel;

            OccurrenceColumnItem occurrenceColumnItem = e.Item.DataItem as OccurrenceColumnItem;
            pnlMultiGroupModeColumnHeading.Visible = occurrenceColumnItem.OccurrenceDisplayMode == OccurrenceDisplayMode.MultiGroup;
            pnlSingleGroupModeColumnHeading.Visible = occurrenceColumnItem.OccurrenceDisplayMode == OccurrenceDisplayMode.ScheduleOccurrenceDate;
            var columnCssClasses = new List<string>();
            columnCssClasses.Add( "board-column" );
            columnCssClasses.Add( "occurrence-column" );

            if ( occurrenceColumnItem.OccurrenceDisplayMode == OccurrenceDisplayMode.MultiGroup )
            {
                columnCssClasses.Add( "occurrence-column-group" );
                var groupType = GroupTypeCache.Get( occurrenceColumnItem.Group.GroupTypeId );
                var lMultiGroupModeColumnGroupNameHtml = e.Item.FindControl( "lMultiGroupModeColumnGroupNameHtml" ) as Literal;
                lMultiGroupModeColumnGroupNameHtml.Text = string.Format(
                    "<i class='{0}'></i> {1}",
                    groupType.IconCssClass,
                    occurrenceColumnItem.Group.Name );

                var selectedGroupId = hfSelectedGroupId.Value.AsInteger();

                bool isSelectedColumn = hfSelectedGroupId.Value.AsInteger() == occurrenceColumnItem.Group.Id;
                if ( isSelectedColumn )
                {
                    columnCssClasses.Add( "occurrence-column-selected" );
                }

                var btnMultiGroupModeColumnSelectedGroup = e.Item.FindControl( "btnMultiGroupModeColumnSelectedGroup" ) as LinkButton;
                if ( isSelectedColumn )
                {
                    btnMultiGroupModeColumnSelectedGroup.Text = "<i class='fa fa-check-square'></i>";
                }
                else
                {
                    btnMultiGroupModeColumnSelectedGroup.Text = "<i class='fa fa-square-o'></i>";
                }

                btnMultiGroupModeColumnSelectedGroup.Attributes["data-group-id"] = occurrenceColumnItem.Group.Id.ToString();
            }
            else if ( occurrenceColumnItem.OccurrenceDisplayMode == OccurrenceDisplayMode.ScheduleOccurrenceDate )
            {
                columnCssClasses.Add( "occurrence-column-schedule" );

                // Single Group mode, so show column header with Schedule Info
                var lSingleGroupModeColumnHeadingOccurrenceDate = e.Item.FindControl( "lSingleGroupModeColumnHeadingOccurrenceDate" ) as Literal;
                var lSingleGroupModeColumnHeadingOccurrenceTime = e.Item.FindControl( "lSingleGroupModeColumnHeadingOccurrenceTime" ) as Literal;

                // show date in 'Sunday, June 15' format
                lSingleGroupModeColumnHeadingOccurrenceDate.Text = occurrenceColumnItem.ScheduledDateTime.Value.ToString( "dddd, MMMM dd" );

                // show time in '10:30 AM' format
                lSingleGroupModeColumnHeadingOccurrenceTime.Text = occurrenceColumnItem.ScheduledDateTime.Value.ToString( "h:mm tt" );
            }
            else
            {
                // shouldn't happen
            }

            var pnlOccurrenceColumn = e.Item.FindControl( "pnlOccurrenceColumn" ) as Panel;
            pnlOccurrenceColumn.CssClass = columnCssClasses.AsDelimited( " " );

            rptAttendanceOccurrences.DataSource = occurrenceColumnItem.AttendanceOccurrenceItems;
            rptAttendanceOccurrences.DataBind();
        }

        /// <summary>
        /// Handles the ItemDataBound event of the rptAttendanceOccurrences control.
        /// </summary>
        /// <param name="sender">The source of the event.</param>
        /// <param name="e">The <see cref="RepeaterItemEventArgs"/> instance containing the event data.</param>
        protected void rptAttendanceOccurrences_ItemDataBound( object sender, RepeaterItemEventArgs e )
        {
            var attendanceOccurrenceRowItem = e.Item.DataItem as AttendanceOccurrenceRowItem;
            var attendanceOccurrenceId = attendanceOccurrenceRowItem.AttendanceOccurrenceId;
            var pnlScheduledOccurrence = e.Item.FindControl( "pnlScheduledOccurrence" ) as Panel;
            var pnlStatusLabels = e.Item.FindControl( "pnlStatusLabels" ) as Panel;

            // hide the scheduled occurrence when it is empty if is the one that doesn't have a Location assigned
            bool hasLocation = attendanceOccurrenceRowItem.LocationId.HasValue;
            pnlScheduledOccurrence.Attributes["data-has-location"] = hasLocation.Bit().ToString();

            // hide the status labels if is the one that doesn't have a Location assigned
            pnlStatusLabels.Visible = hasLocation;


            var pnlMultiGroupModePanelHeading = e.Item.FindControl( "pnlMultiGroupModePanelHeading" ) as Panel;
            var lMultiGroupModeLocationTitle = e.Item.FindControl( "lMultiGroupModeLocationTitle" ) as Literal;
            lMultiGroupModeLocationTitle.Text = attendanceOccurrenceRowItem.LocationName;
            if ( attendanceOccurrenceRowItem.ScheduledDateTime.HasValue )
            {
                var lMultiGroupModeOccurrenceScheduledDate = e.Item.FindControl( "lMultiGroupModeOccurrenceScheduledDate" ) as Literal;
                var lMultiGroupModeOccurrenceScheduledTime = e.Item.FindControl( "lMultiGroupModeOccurrenceScheduledTime" ) as Literal;

                // show date in 'Sunday, June 15' format
                lMultiGroupModeOccurrenceScheduledDate.Text = attendanceOccurrenceRowItem.ScheduledDateTime.Value.ToString( "dddd, MMMM dd" );

                // show time in '10:30 AM' format
                lMultiGroupModeOccurrenceScheduledTime.Text = attendanceOccurrenceRowItem.ScheduledDateTime.Value.ToString( "h:mm tt" );
                pnlScheduledOccurrence.Attributes["data-attendanceoccurrence-date"] = attendanceOccurrenceRowItem.ScheduledDateTime.Value.Date.ToISO8601DateString();
            }

            var pnlSingleGroupModePanelHeading = e.Item.FindControl( "pnlSingleGroupModePanelHeading" ) as Panel;
            var lSingleGroupModeLocationTitle = e.Item.FindControl( "lSingleGroupModeLocationTitle" ) as Literal;
            lSingleGroupModeLocationTitle.Text = attendanceOccurrenceRowItem.LocationName;

            if ( attendanceOccurrenceRowItem.OccurrenceDisplayMode == OccurrenceDisplayMode.MultiGroup )
            {
                pnlMultiGroupModePanelHeading.Visible = true;
                pnlSingleGroupModePanelHeading.Visible = false;
            }
            else
            {
                pnlMultiGroupModePanelHeading.Visible = false;
                pnlSingleGroupModePanelHeading.Visible = true;
            }

            pnlScheduledOccurrence.Attributes["data-attendanceoccurrence-id"] = attendanceOccurrenceId.ToString();

            if ( attendanceOccurrenceRowItem.CapacityInfo != null )
            {
                pnlScheduledOccurrence.Attributes["data-minimum-capacity"] = attendanceOccurrenceRowItem.CapacityInfo.MinimumCapacity.ToString();
                pnlScheduledOccurrence.Attributes["data-desired-capacity"] = attendanceOccurrenceRowItem.CapacityInfo.DesiredCapacity.ToString();
                pnlScheduledOccurrence.Attributes["data-maximum-capacity"] = attendanceOccurrenceRowItem.CapacityInfo.MaximumCapacity.ToString();
            }
        }

        #endregion Methods

        #region Events

        /// <summary>
        /// Handles the Click event of the btnShowChildGroups control.
        /// </summary>
        /// <param name="sender">The source of the event.</param>
        /// <param name="e">The <see cref="EventArgs"/> instance containing the event data.</param>
        protected void btnShowChildGroups_Click( object sender, EventArgs e )
        {
            var showChildGroups = btnShowChildGroups.Attributes["show-child-groups"].AsBoolean();
            SetStateForShowChildGroupsButton( !showChildGroups );
            UpdatePickedGroups();
        }

        /// <summary>
        /// Handles the ValueChanged event of the gpGroup control.
        /// </summary>
        /// <param name="sender">The source of the event.</param>
        /// <param name="e">The <see cref="EventArgs"/> instance containing the event data.</param>
        protected void gpPickedGroups_ValueChanged( object sender, EventArgs e )
        {
            UpdatePickedGroups();
        }

        /// <summary>
        /// Updates the picked groups after the GroupPicker or ShowChildGroups UI controls are changed
        /// </summary>
        private void UpdatePickedGroups()
        {
            // the glListedGroups picker selected the groups that we show in the Scheduler, but only one Group can be the active/selected one
            var pickedGroupIds = gpPickedGroups.SelectedIds.ToList();

            var authorizedListedGroups = GetAuthorizedListedGroups();

            // if there isn't a currently selected group, default to the first one
            var schedulingEnabledGroupIds = GetSchedulingEnabledGroupIds( authorizedListedGroups.Select( a => a.Id ).ToList() );

            var selectedGroupId = hfSelectedGroupId.Value.AsIntegerOrNull();

            if ( selectedGroupId.HasValue )
            {
                // if the currently selectedGroupId is not in the updated listedGroupIds, default the selectedGroupId to the first listed Groupid
                if ( !pickedGroupIds.Contains( selectedGroupId.Value ) || !schedulingEnabledGroupIds.Contains( selectedGroupId.Value ) )
                {
                    selectedGroupId = schedulingEnabledGroupIds.FirstOrDefault();
                }
            }
            else
            {
                selectedGroupId = schedulingEnabledGroupIds.FirstOrDefault();
            }

            hfSelectedGroupId.Value = selectedGroupId.ToString();

            UpdateScheduleList( authorizedListedGroups );
            UpdateLocationList( authorizedListedGroups );
            ApplyFilter();
        }

        /// <summary>
        /// Handles the SelectedIndexChanged event of the ddlWeek control.
        /// </summary>
        /// <param name="sender">The source of the event.</param>
        /// <param name="e">The <see cref="EventArgs"/> instance containing the event data.</param>
        protected void ddlWeek_SelectedIndexChanged( object sender, EventArgs e )
        {
            ApplyFilter();
        }

        /// <summary>
        /// Handles the SelectedIndexChanged event of the cblGroupLocations control.
        /// </summary>
        /// <param name="sender">The source of the event.</param>
        /// <param name="e">The <see cref="EventArgs"/> instance containing the event data.</param>
        protected void cblGroupLocations_SelectedIndexChanged( object sender, EventArgs e )
        {
            ApplyFilter();
        }

        /// <summary>
        /// Handles the Change event of the ResourceListSourceType control.
        /// </summary>
        /// <param name="sender">The source of the event.</param>
        /// <param name="e">The <see cref="EventArgs"/> instance containing the event data.</param>
        protected void ResourceListSourceType_Change( object sender, EventArgs e )
        {
            LinkButton btnResourceListSourceType = sender as LinkButton;

            SchedulerResourceListSourceType schedulerResourceListSourceType = ( SchedulerResourceListSourceType ) btnResourceListSourceType.CommandArgument.AsInteger();
            SchedulerResourceGroupMemberFilterType schedulerResourceGroupMemberFilterType = SchedulerResourceGroupMemberFilterType.ShowAllGroupMembers;

            if ( schedulerResourceListSourceType == SchedulerResourceListSourceType.GroupMatchingPreference )
            {
                schedulerResourceGroupMemberFilterType = SchedulerResourceGroupMemberFilterType.ShowMatchingPreference;
            }

            SetResourceListSourceType( schedulerResourceListSourceType, schedulerResourceGroupMemberFilterType );
            ApplyFilter();
        }

        /// <summary>
        /// Sets the type of the resource list source.
        /// </summary>
        /// <param name="schedulerResourceListSourceType">Type of the scheduler resource list source.</param>
        /// <param name="schedulerResourceGroupMemberFilterType">Type of the scheduler resource group member filter.</param>
        private void SetResourceListSourceType( SchedulerResourceListSourceType schedulerResourceListSourceType, SchedulerResourceGroupMemberFilterType schedulerResourceGroupMemberFilterType )
        {
            hfSchedulerResourceListSourceType.Value = schedulerResourceListSourceType.ConvertToInt().ToString();
            hfResourceGroupMemberFilterType.Value = schedulerResourceGroupMemberFilterType.ConvertToInt().ToString();

            switch ( schedulerResourceListSourceType )
            {
                case SchedulerResourceListSourceType.GroupMembers:
                case SchedulerResourceListSourceType.GroupMatchingPreference:
                    {
                        if ( schedulerResourceGroupMemberFilterType == SchedulerResourceGroupMemberFilterType.ShowMatchingPreference )
                        {
                            lSelectedResourceTypeDropDownText.Text = "Group Members (Matching Preference)";
                        }
                        else
                        {
                            lSelectedResourceTypeDropDownText.Text = "Group Members";
                        }

                        sfResource.Placeholder = "Search";

                        break;
                    }

                case SchedulerResourceListSourceType.AlternateGroup:
                    {
                        lSelectedResourceTypeDropDownText.Text = "Alternate Group";
                        sfResource.Placeholder = "Search Alternate Group";
                        break;
                    }

                case SchedulerResourceListSourceType.DataView:
                    {
                        lSelectedResourceTypeDropDownText.Text = "Data View";
                        sfResource.Placeholder = "Search Data View";
                        break;
                    }

                case SchedulerResourceListSourceType.ParentGroup:
                    {
                        lSelectedResourceTypeDropDownText.Text = "Parent Group";
                        sfResource.Placeholder = "Search Parent Group";
                        break;
                    }

                default:
                    {
                        // another case statement should have done this, but just in case
                        lSelectedResourceTypeDropDownText.Text = "Group Members";
                        sfResource.Placeholder = "Search";
                        break;
                    }
            }
        }

        /// <summary>
        /// Handles the SelectedIndexChanged event of the bgResourceListSource control.
        /// </summary>
        /// <param name="sender">The source of the event.</param>
        /// <param name="e">The <see cref="EventArgs"/> instance containing the event data.</param>
        protected void bgResourceListSource_SelectedIndexChanged( object sender, EventArgs e )
        {
            ApplyFilter();
        }

        /// <summary>
        /// Handles the ValueChanged event of the gpResourceListAlternateGroup control.
        /// </summary>
        /// <param name="sender">The source of the event.</param>
        /// <param name="e">The <see cref="System.EventArgs" /> instance containing the event data.</param>
        protected void gpResourceListAlternateGroup_ValueChanged( object sender, EventArgs e )
        {
            ApplyFilter();
        }

        /// <summary>
        /// Handles the SelectedIndexChanged event of the rblGroupMemberFilter control.
        /// </summary>
        /// <param name="sender">The source of the event.</param>
        /// <param name="e">The <see cref="EventArgs"/> instance containing the event data.</param>
        protected void rblGroupMemberFilter_SelectedIndexChanged( object sender, EventArgs e )
        {
            ApplyFilter();
        }

        /// <summary>
        /// Handles the ValueChanged event of the dvpResourceListDataView control.
        /// </summary>
        /// <param name="sender">The source of the event.</param>
        /// <param name="e">The <see cref="EventArgs"/> instance containing the event data.</param>
        protected void dvpResourceListDataView_ValueChanged( object sender, EventArgs e )
        {
            ApplyFilter();
        }

        /// <summary>
        /// Handles the Click event of the btnAutoSchedule control.
        /// </summary>
        /// <param name="sender">The source of the event.</param>
        /// <param name="e">The <see cref="EventArgs"/> instance containing the event data.</param>
        protected void btnAutoSchedule_Click( object sender, EventArgs e )
        {
            var rockContext = new RockContext();

            var attendanceOccurrenceIdList = hfDisplayedOccurrenceIds.Value.SplitDelimitedValues().AsIntegerList();

            var attendanceService = new AttendanceService( rockContext );

            // AutoSchedule the occurrences that are shown
            attendanceService.SchedulePersonsAutomaticallyForAttendanceOccurrences( attendanceOccurrenceIdList, this.CurrentPersonAlias );
            rockContext.SaveChanges();
        }

        /// <summary>
        /// Handles the Click event of the btnSendNow control.
        /// </summary>
        /// <param name="sender">The source of the event.</param>
        /// <param name="e">The <see cref="EventArgs"/> instance containing the event data.</param>
        protected void btnSendNow_Click( object sender, EventArgs e )
        {
            var rockContext = new RockContext();

            var attendanceOccurrenceIdList = hfDisplayedOccurrenceIds.Value.SplitDelimitedValues().AsIntegerList();

            var attendanceService = new AttendanceService( rockContext );
            var sendConfirmationAttendancesQuery = attendanceService.GetPendingScheduledConfirmations()
                .Where( a => attendanceOccurrenceIdList.Contains( a.OccurrenceId ) )
                .Where( a => a.ScheduleConfirmationSent != true );

            List<string> errorMessages;
            var emailsSent = attendanceService.SendScheduleConfirmationSystemEmails( sendConfirmationAttendancesQuery, out errorMessages );
            bool isSendConfirmationAttendancesFound = sendConfirmationAttendancesQuery.Any();
            rockContext.SaveChanges();

            StringBuilder summaryMessageBuilder = new StringBuilder();
            ModalAlertType alertType;

            if ( errorMessages.Any() )
            {
                alertType = ModalAlertType.Alert;

                var logException = new Exception( "One or more errors occurred when sending confirmation emails: " + Environment.NewLine + errorMessages.AsDelimited( Environment.NewLine ) );

                ExceptionLogService.LogException( logException );

                summaryMessageBuilder.AppendLine( logException.Message );
            }
            else
            {
                alertType = ModalAlertType.Information;
                if ( emailsSent > 0 && isSendConfirmationAttendancesFound )
                {
                    summaryMessageBuilder.AppendLine( string.Format( "Successfully sent {0} confirmation {1}", emailsSent, "email".PluralizeIf( emailsSent != 1 ) ) );
                }
                else
                {
                    summaryMessageBuilder.AppendLine( "Everybody has already been sent a confirmation email. No additional confirmation emails sent." );
                }
            }

            maSendNowResults.Show( summaryMessageBuilder.ToString().ConvertCrLfToHtmlBr(), alertType );
        }

        /// <summary>
        /// Handles the SelectPerson event of the ppAddPerson control.
        /// </summary>
        /// <param name="sender">The source of the event.</param>
        /// <param name="e">The <see cref="EventArgs"/> instance containing the event data.</param>
        protected void ppAddPerson_SelectPerson( object sender, EventArgs e )
        {
            var additionPersonIds = hfResourceAdditionalPersonIds.Value.SplitDelimitedValues().AsIntegerList();
            if ( ppAddPerson.PersonId.HasValue )
            {
                additionPersonIds.Add( ppAddPerson.PersonId.Value );
            }

            hfResourceAdditionalPersonIds.Value = additionPersonIds.AsDelimited( "," );

            // clear on the selected person
            ppAddPerson.SetValue( null );
        }

        /// <summary>
        /// Handles the ItemDataBound event of the rptSchedulerResourceListSourceType control.
        /// </summary>
        /// <param name="sender">The source of the event.</param>
        /// <param name="e">The <see cref="RepeaterItemEventArgs"/> instance containing the event data.</param>
        protected void rptSchedulerResourceListSourceType_ItemDataBound( object sender, RepeaterItemEventArgs e )
        {
            var btnResourceListSourceType = e.Item.FindControl( "btnResourceListSourceType" ) as LinkButton;
            SchedulerResourceListSourceType schedulerResourceListSourceType = ( SchedulerResourceListSourceType ) e.Item.DataItem;
            btnResourceListSourceType.Text = schedulerResourceListSourceType.GetDescription() ?? schedulerResourceListSourceType.ConvertToString( true );
            btnResourceListSourceType.CommandArgument = schedulerResourceListSourceType.ConvertToInt().ToString();
        }

        /// <summary>
        /// Handles the ItemDataBound event of the rptWeekSelector control.
        /// </summary>
        /// <param name="sender">The source of the event.</param>
        /// <param name="e">The <see cref="RepeaterItemEventArgs"/> instance containing the event data.</param>
        protected void rptWeekSelector_ItemDataBound( object sender, RepeaterItemEventArgs e )
        {
            var sundayDate = ( DateTime ) e.Item.DataItem;
            string weekTitle = string.Format( "{0} to {1}", sundayDate.AddDays( -6 ).ToShortDateString(), sundayDate.ToShortDateString() );

            var btnSelectWeek = e.Item.FindControl( "btnSelectWeek" ) as LinkButton;
            btnSelectWeek.Text = weekTitle;
            btnSelectWeek.CommandArgument = sundayDate.ToISO8601DateString();
        }

        /// <summary>
        /// Handles the Click event of the btnSelectWeek control.
        /// </summary>
        /// <param name="sender">The source of the event.</param>
        /// <param name="e">The <see cref="EventArgs"/> instance containing the event data.</param>
        protected void btnSelectWeek_Click( object sender, EventArgs e )
        {
            var btnSelectWeek = sender as LinkButton;
            hfWeekSundayDate.Value = btnSelectWeek.CommandArgument;
            ApplyFilter();
        }

        /// <summary>
        /// Handles the Click event of the btnSelectSchedule control.
        /// </summary>
        /// <param name="sender">The source of the event.</param>
        /// <param name="e">The <see cref="EventArgs"/> instance containing the event data.</param>
        protected void btnSelectSchedule_Click( object sender, EventArgs e )
        {
            var btnSelectSchedule = sender as LinkButton;
            hfSelectedScheduleId.Value = btnSelectSchedule.CommandArgument;

            var authorizedListedGroups = GetAuthorizedListedGroups();

            UpdateLocationList( authorizedListedGroups );
            ApplyFilter();
        }

        /// <summary>
        /// Handles the ItemDataBound event of the rptScheduleSelector control.
        /// </summary>
        /// <param name="sender">The source of the event.</param>
        /// <param name="e">The <see cref="RepeaterItemEventArgs"/> instance containing the event data.</param>
        protected void rptScheduleSelector_ItemDataBound( object sender, RepeaterItemEventArgs e )
        {
            LinkButton btnSelectSchedule = e.Item.FindControl( "btnSelectSchedule" ) as LinkButton;
            var schedule = e.Item.DataItem as Schedule;
            if ( schedule != null )
            {
                btnSelectSchedule.CommandArgument = schedule.Id.ToString();

                if ( schedule.Name.IsNotNullOrWhiteSpace() )
                {
                    btnSelectSchedule.Text = schedule.Name;
                }
                else
                {
                    btnSelectSchedule.Text = schedule.FriendlyScheduleText;
                }
            }
            else
            {
                btnSelectSchedule.CommandArgument = "all";
                btnSelectSchedule.Text = "All Schedules";
            }
        }

        /// <summary>
        /// Handles the Click event of the btnSelectLocation control.
        /// </summary>
        /// <param name="sender">The source of the event.</param>
        /// <param name="sender">The source of the event.</param>
        /// <param name="e">The <see cref="EventArgs"/> instance containing the event data.</param>
        protected void btnSelectLocation_Click( object sender, EventArgs e )
        {
            var btnSelectLocation = sender as LinkButton;

            var selectedLocationId = btnSelectLocation.CommandArgument.AsIntegerOrNull();

            if ( selectedLocationId.HasValue )
            {
                var selectedLocationIds = hfSelectedLocationIds.Value.Split( ',' ).AsIntegerList();

                // toggle if the selected group location is in the selected group locations
                if ( selectedLocationIds.Contains( selectedLocationId.Value ) )
                {
                    selectedLocationIds.Remove( selectedLocationId.Value );
                }
                else
                {
                    selectedLocationIds.Add( selectedLocationId.Value );
                }

                hfSelectedLocationIds.Value = selectedLocationIds.AsDelimited( "," );
            }
            else
            {
                hfSelectedLocationIds.Value = "all";
            }

            ApplyFilter();
        }

        /// <summary>
        /// Handles the ItemDataBound event of the rptGroupLocationSelector control.
        /// </summary>
        /// <param name="sender">The source of the event.</param>
        /// <param name="e">The <see cref="RepeaterItemEventArgs"/> instance containing the event data.</param>
        protected void rptLocationSelector_ItemDataBound( object sender, RepeaterItemEventArgs e )
        {
            LinkButton btnSelectLocation = e.Item.FindControl( "btnSelectLocation" ) as LinkButton;
            Location location = e.Item.DataItem as Location;
            if ( location != null )
            {
                btnSelectLocation.CommandArgument = location.Id.ToString();
                btnSelectLocation.Text = location.ToString();
            }
            else
            {
                btnSelectLocation.CommandArgument = "all";
                btnSelectLocation.Text = "All Locations";
            }
        }

        /// <summary>
        /// Handles the Click event of the btnMultiGroupModeColumnSelectedGroup control.
        /// </summary>
        /// <param name="sender">The source of the event.</param>
        /// <param name="e">The <see cref="EventArgs"/> instance containing the event data.</param>
        protected void btnMultiGroupModeColumnSelectedGroup_Click( object sender, EventArgs e )
        {
            var btnMultiGroupModeColumnSelectedGroup = sender as LinkButton;

            var groupId = btnMultiGroupModeColumnSelectedGroup.Attributes["data-group-id"].AsInteger();
            hfSelectedGroupId.Value = groupId.ToString();
            ApplyFilter();
        }

        #endregion Events


    }
}
