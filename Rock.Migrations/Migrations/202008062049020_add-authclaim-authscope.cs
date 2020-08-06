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
namespace Rock.Migrations
{
    using System;
    using System.Data.Entity.Migrations;

    /// <summary>
    ///
    /// </summary>
    public partial class addauthclaimauthscope : Rock.Migrations.RockMigration
    {
        /// <summary>
        /// Operations to be performed during the upgrade process.
        /// </summary>
        public override void Up()
        {
            CreateTable(
                "dbo.AuthClaim",
                c => new
                {
                    Id = c.Int( nullable: false, identity: true ),
                    IsActive = c.Boolean( nullable: false ),
                    IsSystem = c.Boolean( nullable: false ),
                    Name = c.String( nullable: false, maxLength: 50 ),
                    PublicName = c.String( maxLength: 100 ),
                    ScopeId = c.Int( nullable: false ),
                    Value = c.String(),
                    CreatedDateTime = c.DateTime(),
                    ModifiedDateTime = c.DateTime(),
                    CreatedByPersonAliasId = c.Int(),
                    ModifiedByPersonAliasId = c.Int(),
                    Guid = c.Guid( nullable: false ),
                    ForeignId = c.Int(),
                    ForeignGuid = c.Guid(),
                    ForeignKey = c.String( maxLength: 100 ),
                } )
                .PrimaryKey( t => t.Id )
                .ForeignKey( "dbo.PersonAlias", t => t.CreatedByPersonAliasId )
                .ForeignKey( "dbo.PersonAlias", t => t.ModifiedByPersonAliasId )
                .ForeignKey( "dbo.AuthScope", t => t.ScopeId, cascadeDelete: true )
                .Index( t => t.Name, unique: true )
                .Index( t => t.ScopeId )
                .Index( t => t.Guid, unique: true );

            CreateTable(
                "dbo.AuthScope",
                c => new
                {
                    Id = c.Int( nullable: false, identity: true ),
                    IsActive = c.Boolean( nullable: false ),
                    IsSystem = c.Boolean( nullable: false ),
                    Name = c.String( nullable: false, maxLength: 50 ),
                    PublicName = c.String( maxLength: 100 ),
                    CreatedDateTime = c.DateTime(),
                    ModifiedDateTime = c.DateTime(),
                    CreatedByPersonAliasId = c.Int(),
                    ModifiedByPersonAliasId = c.Int(),
                    Guid = c.Guid( nullable: false ),
                    ForeignId = c.Int(),
                    ForeignGuid = c.Guid(),
                    ForeignKey = c.String( maxLength: 100 ),
                } )
                .PrimaryKey( t => t.Id )
                .ForeignKey( "dbo.PersonAlias", t => t.CreatedByPersonAliasId )
                .ForeignKey( "dbo.PersonAlias", t => t.ModifiedByPersonAliasId )
                .Index( t => t.Name, unique: true )
                .Index( t => t.Guid, unique: true );

            AddColumn( "dbo.AuthClient", "AllowUserApiAccess", c => c.Boolean( nullable: false ) );
            AddColumn( "dbo.AuthClient", "AllowedClaims", c => c.String() );
            AddColumn( "dbo.AuthClient", "AllowedScopes", c => c.String() );

            AddScopes();
            AddClaims();
        }

        /// <summary>
        /// Operations to be performed during the downgrade process.
        /// </summary>
        public override void Down()
        {
            DropForeignKey( "dbo.AuthClaim", "ScopeId", "dbo.AuthScope" );
            DropForeignKey( "dbo.AuthScope", "ModifiedByPersonAliasId", "dbo.PersonAlias" );
            DropForeignKey( "dbo.AuthScope", "CreatedByPersonAliasId", "dbo.PersonAlias" );
            DropForeignKey( "dbo.AuthClaim", "ModifiedByPersonAliasId", "dbo.PersonAlias" );
            DropForeignKey( "dbo.AuthClaim", "CreatedByPersonAliasId", "dbo.PersonAlias" );
            DropIndex( "dbo.AuthScope", new[] { "Guid" } );
            DropIndex( "dbo.AuthScope", new[] { "ModifiedByPersonAliasId" } );
            DropIndex( "dbo.AuthScope", new[] { "CreatedByPersonAliasId" } );
            DropIndex( "dbo.AuthScope", new[] { "Name" } );
            DropIndex( "dbo.AuthClaim", new[] { "Guid" } );
            DropIndex( "dbo.AuthClaim", new[] { "ModifiedByPersonAliasId" } );
            DropIndex( "dbo.AuthClaim", new[] { "CreatedByPersonAliasId" } );
            DropIndex( "dbo.AuthClaim", new[] { "ScopeId" } );
            DropIndex( "dbo.AuthClaim", new[] { "Name" } );
            DropColumn( "dbo.AuthClient", "AllowedScopes" );
            DropColumn( "dbo.AuthClient", "AllowedClaims" );
            DropColumn( "dbo.AuthClient", "AllowUserApiAccess" );
            DropTable( "dbo.AuthScope" );
            DropTable( "dbo.AuthClaim" );
        }

        private string addressGuid = Guid.NewGuid().ToString();
        private string emailGuid = Guid.NewGuid().ToString();
        private string offlineGuid = Guid.NewGuid().ToString();
        private string phoneGuid = Guid.NewGuid().ToString();
        private string profileGuid = Guid.NewGuid().ToString();

        private void AddScopes()
        {
            var sql = $@"INSERT INTO AuthScope ([IsActive], [IsSystem], [Name], [PublicName], [CreatedDateTime], [ModifiedDateTime], [Guid])
                        VALUES (1, 1, 'address', 'Address', GETDATE(), GETDATE(), '{addressGuid}')
                        , (1, 1, 'email', 'Email Address', GETDATE(), GETDATE(), '{emailGuid}')
                        , (1, 1, 'offline_access', 'Allows the use of refresh tokens.', GETDATE(), GETDATE(), '{offlineGuid}')
                        , (1, 1, 'phone', 'Phone Number', GETDATE(), GETDATE(), '{phoneGuid}')
                        , (1, 1, 'profile', 'Profile Information', GETDATE(), GETDATE(), '{profileGuid}')";
            Sql( sql );
        }

        private void AddClaims()
        {
            var sql = $@"INSERT INTO AuthClaim ([IsActive], [IsSystem], [Name], [PublicName], [ScopeId], [CreatedDateTime], [ModifiedDateTime], [Guid])
                        VALUES (1, 1, 'address', 'Address', (SELECT TOP 1 Id FROM AuthScope WHERE [Guid] = '{addressGuid}'), GETDATE(), GETDATE(), NEWID())
                        , (1, 1, 'email', 'Email Address', (SELECT TOP 1 Id FROM AuthScope WHERE [Guid] = '{emailGuid}'), GETDATE(), GETDATE(), NEWID())
                        , (1, 1, 'phone', 'Phone Number', (SELECT TOP 1 Id FROM AuthScope WHERE [Guid] = '{phoneGuid}'), GETDATE(), GETDATE(), NEWID())
                        , (1, 1, 'name', 'Full Name', (SELECT TOP 1 Id FROM AuthScope WHERE [Guid] = '{profileGuid}'), GETDATE(), GETDATE(), NEWID())
                        , (1, 1, 'family_name', 'Last Name', (SELECT TOP 1 Id FROM AuthScope WHERE [Guid] = '{profileGuid}'), GETDATE(), GETDATE(), NEWID())
                        , (1, 1, 'given_name', 'First Name', (SELECT TOP 1 Id FROM AuthScope WHERE [Guid] = '{profileGuid}'), GETDATE(), GETDATE(), NEWID())
                        , (1, 1, 'middle_name', 'Middle Name', (SELECT TOP 1 Id FROM AuthScope WHERE [Guid] = '{profileGuid}'), GETDATE(), GETDATE(), NEWID())
                        , (1, 1, 'nickname', 'Nickname', (SELECT TOP 1 Id FROM AuthScope WHERE [Guid] = '{profileGuid}'), GETDATE(), GETDATE(), NEWID())
                        , (1, 1, 'preferred_username', 'Full Name', (SELECT TOP 1 Id FROM AuthScope WHERE [Guid] = '{profileGuid}'), GETDATE(), GETDATE(), NEWID())
                        , (1, 1, 'picture', 'Photo', (SELECT TOP 1 Id FROM AuthScope WHERE [Guid] = '{profileGuid}'), GETDATE(), GETDATE(), NEWID())
                        , (1, 1, 'gender', 'Gender', (SELECT TOP 1 Id FROM AuthScope WHERE [Guid] = '{profileGuid}'), GETDATE(), GETDATE(), NEWID())";
            Sql( sql );
        }
    }    
}
