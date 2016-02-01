﻿<%@ Control Language="C#" AutoEventWireup="true" CodeFile="ConnectionRequestEntry.ascx.cs" Inherits="RockWeb.Plugins.com_centralaz.Widgets.ConnectionRequestEntry" %>

<asp:UpdatePanel ID="upnlContent" runat="server">
    <ContentTemplate>
                    <Rock:NotificationBox ID="nbSuccess" NotificationBoxType="Success" runat="server" />

        <asp:Panel ID="pnlView" runat="server" CssClass="panel panel-block">
            <div class="panel-heading">
                <h1 class="panel-title"><i class="fa fa-file-text-o"></i>Connection Request Entry</h1>
            </div>

            <div class="panel-body">
                <div class="row">
                    <div class="col-md-3">
                        <Rock:PersonPicker ID="ppPerson" Label="Requestor" runat="server" OnSelectPerson="ppPerson_SelectPerson" />
                    </div>
                    <div class="col-md-3">
                        <Rock:HighlightLabel ID="hlCampus" runat="server" LabelType="Campus" Text="Mesa" />
                    </div>
                </div>

                <div class="well">
                    <asp:Repeater ID="rptConnnectionTypes" runat="server" OnItemDataBound="rptConnnectionTypes_ItemDataBound">
                        <ItemTemplate>
                            <asp:Literal ID="lConnectionTypeName" runat="server" />
                            <Rock:RockCheckBoxList ID="cblOpportunities" runat="server" RepeatDirection="Horizontal" DataTextField="Name" DataValueField="Id" />
                        </ItemTemplate>
                    </asp:Repeater>
                </div>

                <Rock:RockTextBox ID="tbComments" Label="Comments" runat="server" TextMode="MultiLine" Rows="4" ValidateRequestMode="Disabled" />
                <asp:LinkButton ID="lbSubmit" Text="Submit Request" CssClass="btn btn-primary" runat="server" OnClick="lbSubmit_Click" />
            </div>

        </asp:Panel>

    </ContentTemplate>
</asp:UpdatePanel>
