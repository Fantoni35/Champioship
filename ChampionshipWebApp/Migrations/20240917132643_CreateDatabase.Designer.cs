﻿// <auto-generated />
using System;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

#nullable disable

namespace ChampionshipWebApp.Migrations
{
    [DbContext(typeof(FootballLeagueContext))]
    [Migration("20240917132643_CreateDatabase")]
    partial class CreateDatabase
    {
        /// <inheritdoc />
        protected override void BuildTargetModel(ModelBuilder modelBuilder)
        {
#pragma warning disable 612, 618
            modelBuilder.HasAnnotation("ProductVersion", "8.0.8");

            modelBuilder.Entity("Championship.Match", b =>
                {
                    b.Property<int>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("INTEGER");

                    b.Property<int>("AwayTeamId")
                        .HasColumnType("INTEGER");

                    b.Property<string>("City")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("HomeTeamId")
                        .HasColumnType("INTEGER");

                    b.Property<DateTime>("MatchDate")
                        .HasColumnType("TEXT");

                    b.Property<int?>("ResultId")
                        .HasColumnType("INTEGER");

                    b.Property<string>("StadiumName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.HasIndex("AwayTeamId");

                    b.HasIndex("HomeTeamId");

                    b.HasIndex("ResultId");

                    b.ToTable("Matches", (string)null);
                });

            modelBuilder.Entity("Championship.MatchResult", b =>
                {
                    b.Property<int>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("INTEGER");

                    b.Property<int>("AwayTeamScore")
                        .HasColumnType("INTEGER");

                    b.Property<int>("HomeTeamScore")
                        .HasColumnType("INTEGER");

                    b.HasKey("Id");

                    b.ToTable("MatchResults", (string)null);
                });

            modelBuilder.Entity("Championship.Team", b =>
                {
                    b.Property<int>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("INTEGER");

                    b.Property<string>("City")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("ColorOfClub")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("FondationYear")
                        .HasColumnType("INTEGER");

                    b.Property<string>("SquadName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("StadiumName")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.ToTable("Teams", (string)null);
                });

            modelBuilder.Entity("Championship.Match", b =>
                {
                    b.HasOne("Championship.Team", "AwayTeam")
                        .WithMany()
                        .HasForeignKey("AwayTeamId")
                        .OnDelete(DeleteBehavior.Restrict)
                        .IsRequired();

                    b.HasOne("Championship.Team", "HomeTeam")
                        .WithMany()
                        .HasForeignKey("HomeTeamId")
                        .OnDelete(DeleteBehavior.Restrict)
                        .IsRequired();

                    b.HasOne("Championship.MatchResult", "Result")
                        .WithMany()
                        .HasForeignKey("ResultId");

                    b.Navigation("AwayTeam");

                    b.Navigation("HomeTeam");

                    b.Navigation("Result");
                });
#pragma warning restore 612, 618
        }
    }
}
