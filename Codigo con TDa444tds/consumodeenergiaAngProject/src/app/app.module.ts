import { NgModule } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';

import { AppComponent } from './app.component';
import { UserAccountComponent } from './user-account/user-account.component';
import { EnergyQualityComponent } from './energy-quality/energy-quality.component';
import { EnergyFlowSensorComponent } from './energy-flow-sensor/energy-flow-sensor.component';
import { ConsumptionHistoryComponent } from './consumption-history/consumption-history.component';
import { EnergyReportComponent } from './energy-report/energy-report.component';
import { EnergyRateComponent } from './energy-rate/energy-rate.component';
import { EnergyRateSettingsComponent } from './energy-rate-settings/energy-rate-settings.component';

@NgModule({
  declarations: [
    AppComponent,
    UserAccountComponent,
    EnergyQualityComponent,
    EnergyFlowSensorComponent,
    ConsumptionHistoryComponent,
    EnergyReportComponent,
    EnergyRateComponent,
    EnergyRateSettingsComponent
  ],
  imports: [
    BrowserModule
  ],
  providers: [],
  bootstrap: [AppComponent]
})
export class AppModule { }
