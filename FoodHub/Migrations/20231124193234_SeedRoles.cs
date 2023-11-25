using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace FoodHub.Migrations
{
    /// <inheritdoc />
    public partial class SeedRoles : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[,]
                {
                    { "35ca570d-a1ce-4ebe-b1c5-2513c9101351", "3", "Delivery", "delivery" },
                    { "90afaaf0-4951-42f7-993e-f94c27aea9a8", "2", "User", "user" },
                    { "f5f07311-765e-4df7-949c-22aabb7e5027", "1", "Admin", "admin" }
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "35ca570d-a1ce-4ebe-b1c5-2513c9101351");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "90afaaf0-4951-42f7-993e-f94c27aea9a8");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "f5f07311-765e-4df7-949c-22aabb7e5027");
        }
    }
}
