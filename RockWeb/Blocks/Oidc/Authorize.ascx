<%@ Control Language="C#" AutoEventWireup="true" CodeFile="Authorize.ascx.cs" Inherits="RockWeb.Blocks.Oidc.Authorize" %>

<asp:UpdatePanel ID="upnlContent" runat="server">
    <ContentTemplate>

        <Rock:NotificationBox ID="nbNotificationBox" runat="server" NotificationBoxType="Danger" Visible="false" Title="Error" />

        <asp:Panel ID="pnlPanel" CssClass="panel panel-block" runat="server">
            <div class="panel-heading">
                <h1 class="panel-title">
                    <i class="fa fa-key"></i>
                    Authorization
                </h1>
            </div>
            <div class="panel-body">
                <p>Would you like to grant <asp:Literal ID="lClientName" runat="server" /> access to your information:</p>

                <ul>
                    <asp:Repeater ID="rScopes" runat="server">
                        <ItemTemplate>
                            <li><%# Eval("Name") %></li>
                        </ItemTemplate>
                    </asp:Repeater>
                </ul>

                <div class="actions">
                    <asp:LinkButton ID="btnAccept" runat="server" Text="Yes" CssClass="btn btn-success" OnClick="btnAllow_Click" />
                    <asp:LinkButton ID="btnDeny" runat="server" Text="No" CssClass="btn btn-default" OnClick="btnDeny_Click" />
                </div>
            </div>
        </asp:Panel>

    </ContentTemplate>
</asp:UpdatePanel>


