// <auto-generated />
namespace Rock.Migrations
{
    using System.CodeDom.Compiler;
    using System.Data.Entity.Migrations;
    using System.Data.Entity.Migrations.Infrastructure;
    using System.Resources;
    
    [GeneratedCode("EntityFramework.Migrations", "6.1.3-40302")]
    public sealed partial class AddCcAndBccToSendEmailAction : IMigrationMetadata
    {
        private readonly ResourceManager Resources = new ResourceManager(typeof(AddDateKeyToSelectTables));
        
        string IMigrationMetadata.Id
        {
            get { return "202003252005422_AddCcAndBccToSendEmailAction"; }
        }
        
        string IMigrationMetadata.Source
        {
            get { return null; }
        }
        
        string IMigrationMetadata.Target
        {
            get { return Resources.GetString("Target"); }
        }
    }
}