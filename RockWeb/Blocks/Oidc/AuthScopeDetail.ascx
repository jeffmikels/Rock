<%@ Control Language="C#" AutoEventWireup="true" CodeFile="AuthScopeDetail.ascx.cs" Inherits="RockWeb.Blocks.Oidc.AuthScopeDetail" %>

<asp:UpdatePanel ID="upnlRestKeys" runat="server">
    <ContentTemplate>
        <asp:Panel ID="pnlDetails" CssClass="panel panel-block" runat="server">
            <div class="panel-heading">
                <h1 class="panel-title"><i class="fa fa-openid"></i>
                    <asp:Literal ID="lTitle" runat="server" /></h1>
            </div>
            <div class="panel-body">
                <Rock:NotificationBox ID="nbWarningMessage" runat="server" NotificationBoxType="Warning" />
                <div id="pnlEditDetails" runat="server">
                    <asp:ValidationSummary ID="valSummary" runat="server" HeaderText="Please correct the following:" CssClass="alert alert-validation" />
                    <asp:HiddenField ID="hfRestUserId" runat="server" />
                    <div class="row">
                        <div class="col-md-12">
                            <div class="row">
                                <div class="col-md-12">
                                    <div class="control-label">Name</div>
                                </div>
                            </div>
                            <div class="row">
                                <div class="col-sm-6">
                                    <Rock:RockTextBox ID="tbName" Required="true" runat="server" MaxLength="50" CssClass="form-group" />
                                    <asp:RegularExpressionValidator id="regValidator" ControlToValidate="tbName" runat="server" ValidationExpression="^[a-zA-Z0-9_]*$" Display="None" ErrorMessage="Only alphanumeric and underscore characters can be used." />
                                </div>
                                <div class="col-sm-6">
                                    <div class="row">
                                        <div class="col-xs-6">
                                            <Rock:RockCheckBox ID="cbActive" runat="server" Checked="true" Text="Active" />
                                        </div>
                                        <div class="col-xs-6">
                                            <Rock:RockCheckBox ID="cbIsSystem" runat="server" Checked="false" Enabled="false" Text="System" />
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="row">
                        <div class="col-md-12">
                            <div class="row">
                                <div class="col-md-12">
                                    <div class="control-label">Public Name</div>
                                </div>
                            </div>
                            <div class="row">
                                <div class="col-sm-12">
                                    <Rock:RockTextBox ID="tbPublicName"  MaxLength="100" runat="server" CssClass="form-group" />
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="actions">
                        <asp:LinkButton ID="lbSave" runat="server" AccessKey="s" ToolTip="Alt+s" Text="Save" CssClass="btn btn-primary" OnClick="lbSave_Click" />
                        <asp:LinkButton ID="lbCancel" runat="server" AccessKey="c" ToolTip="Alt+c" Text="Cancel" CssClass="btn btn-link" CausesValidation="false" OnClick="lbCancel_Click" />
                    </div>
                </div>
            </div>
        </asp:Panel>
    </ContentTemplate>
</asp:UpdatePanel>
