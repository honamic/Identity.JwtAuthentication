using System;
using System.Linq;
using System.IO;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.OpenApi.Models;
using Honamic.Identity.JwtAuthentication.Sample.Data;

namespace Honamic.Identity.JwtAuthentication.Sample
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlServer(
                    Configuration.GetConnectionString("DefaultConnection")));



            services.AddIdentity<IdentityUser, IdentityRole>(options =>
             {
                 options.SignIn.RequireConfirmedAccount = true;
                 options.Password.RequiredUniqueChars = 0;
                 options.Password.RequireDigit = false;
                 options.Password.RequireNonAlphanumeric = false;
                 options.Password.RequireUppercase = false;
             })
              .AddEntityFrameworkStores<ApplicationDbContext>()
             .AddDefaultUI()
             .AddDefaultTokenProviders();

            services.AddControllers();
            services.AddRazorPages();

            services.AddSwaggerGen(setupAction =>
            {
                setupAction.SwaggerDoc(
                   name: "BackendOpenAPISpecification",
                   info: new Microsoft.OpenApi.Models.OpenApiInfo()
                   {
                       Title = "Identity Jwt",
                       Version = "1",
                       Description = "Identity jwt Sample Project"
                   });

                setupAction.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
                {
                    In = ParameterLocation.Header,
                    Description = "JWT Authorization header using the Bearer scheme. Example: \"Authorization: Bearer {token}\"",
                    Name = "Authorization",
                    Type = SecuritySchemeType.ApiKey
                });

                setupAction.AddSecurityRequirement(new OpenApiSecurityRequirement {
                   {
                     new OpenApiSecurityScheme
                     {
                       Reference = new OpenApiReference
                       {
                         Type = ReferenceType.SecurityScheme,
                         Id = "Bearer"
                       }
                      },
                      new string[] {"" }
                    }
                  });

                var xmlFiles = Directory.GetFiles(AppContext.BaseDirectory, "*.xml", SearchOption.TopDirectoryOnly).ToList();
                xmlFiles.ForEach(xmlFile => setupAction.IncludeXmlComments(xmlFile));

            });


            services.AddAuthentication()
                .AddJwtAuthentication<IdentityUser>(Configuration);
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseDatabaseErrorPage();
            }
            else
            {
                app.UseExceptionHandler("/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseSwagger();
            app.UseSwaggerUI(setupAction =>
            {
                setupAction.SwaggerEndpoint(
                    url: "/swagger/BackendOpenAPISpecification/swagger.json",
                    name: "Backend API");
                setupAction.RoutePrefix = "swagger";
            });

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapRazorPages();
                endpoints.MapControllers();
            });
        }
    }
}
