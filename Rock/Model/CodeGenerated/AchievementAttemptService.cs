//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated by the Rock.CodeGeneration project
//     Changes to this file will be lost when the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------
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
using System.Linq;

using Rock.Data;

namespace Rock.Model
{
    /// <summary>
    /// AchievementAttempt Service class
    /// </summary>
    public partial class AchievementAttemptService : Service<AchievementAttempt>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AchievementAttemptService"/> class
        /// </summary>
        /// <param name="context">The context.</param>
        public AchievementAttemptService(RockContext context) : base(context)
        {
        }

        /// <summary>
        /// Determines whether this instance can delete the specified item.
        /// </summary>
        /// <param name="item">The item.</param>
        /// <param name="errorMessage">The error message.</param>
        /// <returns>
        ///   <c>true</c> if this instance can delete the specified item; otherwise, <c>false</c>.
        /// </returns>
        public bool CanDelete( AchievementAttempt item, out string errorMessage )
        {
            errorMessage = string.Empty;
            return true;
        }
    }

    /// <summary>
    /// Generated Extension Methods
    /// </summary>
    public static partial class AchievementAttemptExtensionMethods
    {
        /// <summary>
        /// Clones this AchievementAttempt object to a new AchievementAttempt object
        /// </summary>
        /// <param name="source">The source.</param>
        /// <param name="deepCopy">if set to <c>true</c> a deep copy is made. If false, only the basic entity properties are copied.</param>
        /// <returns></returns>
        public static AchievementAttempt Clone( this AchievementAttempt source, bool deepCopy )
        {
            if (deepCopy)
            {
                return source.Clone() as AchievementAttempt;
            }
            else
            {
                var target = new AchievementAttempt();
                target.CopyPropertiesFrom( source );
                return target;
            }
        }

        /// <summary>
        /// Copies the properties from another AchievementAttempt object to this AchievementAttempt object
        /// </summary>
        /// <param name="target">The target.</param>
        /// <param name="source">The source.</param>
        public static void CopyPropertiesFrom( this AchievementAttempt target, AchievementAttempt source )
        {
            target.Id = source.Id;
            target.AchievementAttemptEndDateTime = source.AchievementAttemptEndDateTime;
            target.AchievementAttemptStartDateTime = source.AchievementAttemptStartDateTime;
            target.AchievementTypeId = source.AchievementTypeId;
            target.AchieverEntityId = source.AchieverEntityId;
            target.ForeignGuid = source.ForeignGuid;
            target.ForeignKey = source.ForeignKey;
            target.IsClosed = source.IsClosed;
            target.IsSuccessful = source.IsSuccessful;
            target.Progress = source.Progress;
            target.CreatedDateTime = source.CreatedDateTime;
            target.ModifiedDateTime = source.ModifiedDateTime;
            target.CreatedByPersonAliasId = source.CreatedByPersonAliasId;
            target.ModifiedByPersonAliasId = source.ModifiedByPersonAliasId;
            target.Guid = source.Guid;
            target.ForeignId = source.ForeignId;

        }
    }
}