import { ComponentFixture, TestBed } from '@angular/core/testing';

import { EnergyQualityComponent } from './energy-quality.component';

describe('EnergyQualityComponent', () => {
  let component: EnergyQualityComponent;
  let fixture: ComponentFixture<EnergyQualityComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      declarations: [ EnergyQualityComponent ]
    })
    .compileComponents();

    fixture = TestBed.createComponent(EnergyQualityComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
